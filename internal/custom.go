package internal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// PaymentCtx handles Razorpay order creation, verification, and plan activation.
type PaymentCtx struct {
	db      *mongo.Database
	userCol *mongo.Collection
	entCol  *mongo.Collection
}

func NewPaymentCtx(db *mongo.Database) *PaymentCtx {
	return &PaymentCtx{
		db:      db,
		userCol: db.Collection("user"),
		entCol:  db.Collection("enterprise"),
	}
}

func (p *PaymentCtx) Register(r *mux.Router) {
	r.HandleFunc("/payment/create-order", p.CreateOrder).Methods("POST")
	r.HandleFunc("/payment/verify", p.VerifyPayment).Methods("POST")
	r.HandleFunc("/trial/start", p.StartTrial).Methods("POST")
	// Pause patient-facing booking once a doctor's trial / plan has lapsed.
	r.Use(p.planGuard)
}

// planAmount is ₹1999/year in paise.
const planAmount = 199900

// trialDays returns the trial length from TRIAL_DAYS env var (default 3).
func trialDays() int {
	if s := os.Getenv("TRIAL_DAYS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 3
}

func trialDuration() time.Duration { return time.Duration(trialDays()) * 24 * time.Hour }

type createOrderReq struct {
	Slug       string `json:"slug"`
	DoctorName string `json:"doctorName"`
}

type createOrderResp struct {
	OrderID  string `json:"orderId"`
	Amount   int    `json:"amount"`
	Currency string `json:"currency"`
	Key      string `json:"key"`
}

// CreateOrder creates a Razorpay order for the annual plan.
// Requires the doctor to be logged in (any role — even SELF_USER before plan purchase).
func (p *PaymentCtx) CreateOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok || claims == nil {
		respondErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createOrderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Slug == "" || req.DoctorName == "" {
		respondErr(w, http.StatusBadRequest, "Please enter your name and choose a web address for your booking page")
		return
	}

	// The web address must be free — unless it already belongs to this doctor,
	// which is the case when they're upgrading from a trial to the paid plan.
	if existing := p.entCol.FindOne(ctx, bson.M{"id": req.Slug, "deleted": false}); existing.Err() == nil {
		var doc struct {
			Claims struct {
				UserID string `bson:"userID"`
			} `bson:"claims"`
		}
		_ = existing.Decode(&doc)
		userID, _ := claims["userID"].(string)
		if doc.Claims.UserID != userID {
			respondErr(w, http.StatusConflict, "That web address is already in use. Please choose a different one for your booking page.")
			return
		}
	}

	orderID, err := razorpayCreateOrder(ctx, planAmount)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to create payment order")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createOrderResp{
		OrderID:  orderID,
		Amount:   planAmount,
		Currency: "INR",
		Key:      os.Getenv("RAZORPAY_KEY_ID"),
	})
}

type verifyReq struct {
	RazorpayOrderID   string `json:"razorpayOrderId"`
	RazorpayPaymentID string `json:"razorpayPaymentId"`
	RazorpaySignature string `json:"razorpaySignature"`
	Slug              string `json:"slug"`
	DoctorName        string `json:"doctorName"`
}

type verifyResp struct {
	AccessToken  string `json:"accessToken"`
	EnterpriseID string `json:"enterpriseId"`
}

// VerifyPayment verifies the Razorpay signature, then either converts the
// doctor's running trial to a paid year or (for a direct purchase) creates the
// enterprise doc. It makes sure the user is an ENTERPRISE_USER and returns a
// fresh JWT.
func (p *PaymentCtx) VerifyPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok || claims == nil {
		respondErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))

	if !razorpayVerifySignature(req.RazorpayOrderID, req.RazorpayPaymentID, req.RazorpaySignature) {
		respondErr(w, http.StatusBadRequest, "payment verification failed")
		return
	}

	userID, _ := claims["userID"].(string)
	now := time.Now()

	var entDoc struct {
		Claims struct {
			UserID string `bson:"userID"`
		} `bson:"claims"`
		Data struct {
			PlanExpiry interface{} `bson:"planExpiry"`
		} `bson:"data"`
	}
	findErr := p.entCol.FindOne(ctx, bson.M{"id": req.Slug, "deleted": false}).Decode(&entDoc)

	if findErr == nil {
		// The booking page already exists (typically an active trial) — extend it.
		if entDoc.Claims.UserID != "" && entDoc.Claims.UserID != userID {
			respondErr(w, http.StatusConflict, "That web address was just taken by someone else. Please go back and choose a different one for your booking page.")
			return
		}
		base := now
		if t := planExpiryTime(entDoc.Data.PlanExpiry); t.After(now) {
			base = t
		}
		_, err := p.entCol.UpdateOne(ctx,
			bson.M{"id": req.Slug, "deleted": false},
			bson.D{{Key: "$set", Value: bson.D{
				{Key: "data.doctorName", Value: req.DoctorName},
				{Key: "data.planExpiry", Value: base.AddDate(1, 0, 0)},
				{Key: "data.planActivatedAt", Value: now},
				{Key: "data.trial", Value: false},
				{Key: "data.razorpayOrderId", Value: req.RazorpayOrderID},
				{Key: "data.razorpayPaymentId", Value: req.RazorpayPaymentID},
			}}},
		)
		if err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to activate plan")
			return
		}
	} else {
		// Direct purchase without a trial — create the enterprise doc.
		_, err := p.entCol.InsertOne(ctx, map[string]interface{}{
			"_id": primitive.NewObjectID(),
			"id":  req.Slug,
			"data": map[string]interface{}{
				"doctorName":        req.DoctorName,
				"planExpiry":        now.AddDate(1, 0, 0),
				"planActivatedAt":   now,
				"trial":             false,
				"razorpayOrderId":   req.RazorpayOrderID,
				"razorpayPaymentId": req.RazorpayPaymentID,
			},
			"claims": map[string]interface{}{
				"roles":  []string{"meta"},
				"userID": userID,
			},
			"auditAttr": map[string]interface{}{
				"createdBy": userID,
				"createdAt": now,
			},
			"deleted": false,
		})
		if err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to create enterprise")
			return
		}
	}

	accessToken, err := p.upgradeUserToEnterprise(ctx, claims, req.Slug)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to upgrade user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verifyResp{
		AccessToken:  accessToken,
		EnterpriseID: req.Slug,
	})
}

type startTrialReq struct {
	Slug       string `json:"slug"`
	DoctorName string `json:"doctorName"`
}

// StartTrial creates the enterprise doc with a short trial window (no payment)
// and upgrades the signed-in user to ENTERPRISE_USER so they can use the
// dashboard right away.
func (p *PaymentCtx) StartTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok || claims == nil {
		respondErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req startTrialReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Slug == "" || req.DoctorName == "" {
		respondErr(w, http.StatusBadRequest, "Please enter your name and choose a web address for your booking page")
		return
	}

	// One booking page per doctor.
	if entID, _ := claims["entID"].(string); entID != "" {
		respondErr(w, http.StatusConflict, "You already have a booking page.")
		return
	}

	if existing := p.entCol.FindOne(ctx, bson.M{"id": req.Slug, "deleted": false}); existing.Err() == nil {
		respondErr(w, http.StatusConflict, "That web address is already in use. Please choose a different one for your booking page.")
		return
	}

	userID, _ := claims["userID"].(string)
	now := time.Now()
	_, err := p.entCol.InsertOne(ctx, map[string]interface{}{
		"_id": primitive.NewObjectID(),
		"id":  req.Slug,
		"data": map[string]interface{}{
			"doctorName":     req.DoctorName,
			"planExpiry":     now.Add(trialDuration()),
			"trial":          true,
			"trialStartedAt": now,
		},
		"claims": map[string]interface{}{
			"roles":  []string{"meta"},
			"userID": userID,
		},
		"auditAttr": map[string]interface{}{
			"createdBy": userID,
			"createdAt": now,
		},
		"deleted": false,
	})
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to start trial")
		return
	}

	accessToken, err := p.upgradeUserToEnterprise(ctx, claims, req.Slug)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to activate account")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verifyResp{
		AccessToken:  accessToken,
		EnterpriseID: req.Slug,
	})
}

// upgradeUserToEnterprise merges the "ent" role + entID into the user's claims,
// persists them on the user doc, and returns a fresh signed JWT.
func (p *PaymentCtx) upgradeUserToEnterprise(ctx context.Context, claims jwt.MapClaims, slug string) (string, error) {
	userID, _ := claims["userID"].(string)

	newClaims := map[string]interface{}{}
	for k, v := range claims {
		newClaims[k] = v
	}
	newRoles := appendUnique(extractRolesFromClaims(claims), "ent")
	newClaims["roles"] = newRoles
	newClaims["entID"] = slug

	if _, err := p.userCol.UpdateOne(ctx,
		bson.M{"claims.userID": userID, "deleted": false},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "claims.roles", Value: newRoles},
			{Key: "claims.entID", Value: slug},
		}}},
	); err != nil {
		return "", err
	}

	uData := map[string]interface{}{}
	if ud, ok := claims["uData"].(map[string]interface{}); ok {
		uData = ud
	}
	return buildToken(newClaims, uData)
}

// planGuard blocks patient-facing booking endpoints when the doctor's trial or
// paid plan has lapsed. Doctors keep dashboard access so they can pay.
func (p *PaymentCtx) planGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var entID string
		switch {
		case r.URL.Path == "/api/v1/available/slots":
			entID = r.URL.Query().Get("entID")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/appointments":
			entID = peekEntIDFromBody(r)
		}
		if entID != "" {
			if err := checkPlanExpiry(r.Context(), p.entCol, entID); err != nil && err.Error() == "plan_expired" {
				respondErr(w, http.StatusPaymentRequired, "This booking page isn't active right now. Please contact the clinic directly to book an appointment.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// peekEntIDFromBody reads data.entID from a JSON request body without consuming
// it — the body is restored for the downstream handler.
func peekEntIDFromBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	var payload struct {
		Data struct {
			EntID string `json:"entID"`
		} `json:"data"`
	}
	_ = json.Unmarshal(b, &payload)
	return payload.Data.EntID
}

// planExpiryTime normalises a stored planExpiry value to time.Time.
func planExpiryTime(v interface{}) time.Time {
	switch t := v.(type) {
	case primitive.DateTime:
		return t.Time()
	case time.Time:
		return t
	}
	return time.Time{}
}

// razorpayCreateOrder calls Razorpay Orders API and returns the order ID.
func razorpayCreateOrder(ctx context.Context, amount int) (string, error) {
	keyID := os.Getenv("RAZORPAY_KEY_ID")
	keySecret := os.Getenv("RAZORPAY_KEY_SECRET")

	payload := map[string]interface{}{
		"amount":   amount,
		"currency": "INR",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.razorpay.com/v1/orders", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(keyID, keySecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("razorpay error: %s", string(respBody))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	id, ok := result["id"].(string)
	if !ok {
		return "", fmt.Errorf("no id in razorpay response")
	}
	return id, nil
}

// razorpayVerifySignature verifies the HMAC-SHA256 payment signature.
func razorpayVerifySignature(orderID, paymentID, signature string) bool {
	secret := os.Getenv("RAZORPAY_KEY_SECRET")
	payload := orderID + "|" + paymentID
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// buildToken signs a JWT with the same secret refinery uses.
func buildToken(claims map[string]interface{}, uData map[string]interface{}) (string, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))
	expiry := time.Now().Add(24 * time.Hour * 365)

	// Strip timing claims that refinery's CleanClaims would remove
	clean := map[string]interface{}{}
	skip := map[string]bool{"exp": true, "iat": true, "nbf": true}
	for k, v := range claims {
		if !skip[k] {
			clean[k] = v
		}
	}

	tokenClaims := jwt.MapClaims{
		"claims": clean,
		"uData":  uData,
		"exp":    expiry.Unix(),
		"iat":    time.Now().Unix(),
		"expiry": expiry.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	return token.SignedString(secret)
}

func extractRolesFromClaims(claims jwt.MapClaims) []string {
	roles := make([]string, 0)
	if val, ok := claims["roles"]; ok {
		switch v := val.(type) {
		case []string:
			roles = append(roles, v...)
		case []interface{}:
			for _, r := range v {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	return roles
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func respondErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// OneTapCtx handles Google One-Tap ID token verification and JWT issuance.
// Refinery's /auth/google/token expects an OAuth2 refresh token, which is
// incompatible with the One-Tap credential (an ID token). This handler
// verifies the ID token directly via Google's tokeninfo endpoint.
type OneTapCtx struct {
	userCol *mongo.Collection
}

func NewOneTapCtx(db *mongo.Database) *OneTapCtx {
	return &OneTapCtx{userCol: db.Collection("user")}
}

func (o *OneTapCtx) Register(r *mux.Router) {
	r.HandleFunc("/auth/google/onetap", o.HandleOneTap).Methods("POST", "OPTIONS")
}

type oneTapReq struct {
	Credential string `json:"token"`
}

type oneTapResp struct {
	AccessToken string                 `json:"accessToken"`
	UData       map[string]interface{} `json:"uData"`
}

func (o *OneTapCtx) HandleOneTap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req oneTapReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Credential == "" {
		respondErr(w, http.StatusBadRequest, "credential is required")
		return
	}

	// Verify the ID token with Google and get user info
	tokenInfoURL := "https://oauth2.googleapis.com/tokeninfo?id_token=" + req.Credential
	resp, err := http.Get(tokenInfoURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		respondErr(w, http.StatusUnauthorized, "invalid google token")
		return
	}
	defer resp.Body.Close()

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		respondErr(w, http.StatusUnauthorized, "failed to parse google token info")
		return
	}

	email, _ := info["email"].(string)
	if email == "" {
		respondErr(w, http.StatusUnauthorized, "no email in google token")
		return
	}

	uData := map[string]interface{}{
		"email": email,
		"name":  info["name"],
	}
	if pic, ok := info["picture"].(string); ok {
		uData["picture"] = pic
	}

	// Find or create user by email
	ctx := r.Context()
	var userDoc map[string]interface{}
	err = o.userCol.FindOne(ctx, bson.M{"data.email": email, "deleted": false}).Decode(&userDoc)

	var userClaims map[string]interface{}
	if err != nil {
		// New user — create with SELF_USER role
		userID := primitive.NewObjectID()
		userClaims = map[string]interface{}{
			"userID": userID.Hex(),
			"roles":  []string{"self"},
		}
		_, _ = o.userCol.InsertOne(ctx, bson.M{
			"_id":     userID,
			"data":    uData,
			"claims":  userClaims,
			"deleted": false,
			"auditAttr": bson.M{
				"createdAt": time.Now(),
			},
		})
	} else {
		// Existing user — read their stored claims (preserves ent role if already paid)
		if c, ok := userDoc["claims"].(map[string]interface{}); ok {
			userClaims = c
		} else {
			userClaims = map[string]interface{}{"roles": []string{"self"}}
		}
		// Refresh uData in DB
		_, _ = o.userCol.UpdateOne(ctx,
			bson.M{"data.email": email, "deleted": false},
			bson.M{"$set": bson.M{"data.name": uData["name"], "data.picture": uData["picture"]}},
		)
	}

	expiry := time.Now().Add(24 * time.Hour * 365)
	jwtClaims := jwt.MapClaims{}
	for k, v := range userClaims {
		jwtClaims[k] = v
	}
	accessToken, err := buildToken(jwtClaims, uData)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to build token")
		return
	}
	_ = expiry

	json.NewEncoder(w).Encode(oneTapResp{AccessToken: accessToken, UData: uData})
}

// ProfileCtx lets an enterprise user read and update their own enterprise doc.
// Refinery's built-in enterprise resource is META-only for read/patch, so we
// expose dedicated routes that scope access to the JWT's entID.
type ProfileCtx struct {
	entCol *mongo.Collection
}

func NewProfileCtx(db *mongo.Database) *ProfileCtx {
	return &ProfileCtx{entCol: db.Collection("enterprise")}
}

func (p *ProfileCtx) Register(r *mux.Router) {
	r.HandleFunc("/api/v1/myprofile", p.GetProfile).Methods("GET")
	r.HandleFunc("/api/v1/myprofile", p.UpdateProfile).Methods("PATCH")
}

// claimsMapFromCtx extracts the nested claims from context.
// Refinery's AuthMiddleware stores tokenPayload["claims"] as jwt.MapClaims
// under context key "claims" — so entID, userID, roles are at the top level.
func claimsMapFromCtx(r *http.Request) jwt.MapClaims {
	if c, ok := r.Context().Value("claims").(jwt.MapClaims); ok {
		return c
	}
	return nil
}

func (p *ProfileCtx) GetProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims := claimsMapFromCtx(r)
	entID, _ := claims["entID"].(string)
	if entID == "" {
		respondErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var doc map[string]interface{}
	err := p.entCol.FindOne(r.Context(), bson.M{"id": entID, "deleted": false}).Decode(&doc)
	if err != nil {
		respondErr(w, http.StatusNotFound, "profile not found")
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"data": doc})
}

func (p *ProfileCtx) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims := claimsMapFromCtx(r)
	entID, _ := claims["entID"].(string)
	if entID == "" {
		respondErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	// Build $set update from the request body
	setDoc := bson.D{}
	for k, v := range body {
		setDoc = append(setDoc, bson.E{Key: k, Value: v})
	}
	if len(setDoc) == 0 {
		respondErr(w, http.StatusBadRequest, "nothing to update")
		return
	}

	_, err := p.entCol.UpdateOne(r.Context(),
		bson.M{"id": entID, "deleted": false},
		bson.D{{Key: "$set", Value: setDoc}},
	)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// checkPlanExpiry returns an error when the enterprise's plan has passed its expiry date.
func checkPlanExpiry(ctx context.Context, entCol *mongo.Collection, entID string) error {
	if entID == "" {
		return fmt.Errorf("no entID")
	}
	var doc struct {
		Data struct {
			PlanExpiry interface{} `bson:"planExpiry"`
		} `bson:"data"`
	}
	if err := entCol.FindOne(ctx, bson.M{"id": entID, "deleted": false}).Decode(&doc); err != nil {
		return fmt.Errorf("enterprise not found")
	}
	if doc.Data.PlanExpiry == nil {
		return nil
	}
	switch v := doc.Data.PlanExpiry.(type) {
	case primitive.DateTime:
		if time.Now().After(v.Time()) {
			return fmt.Errorf("plan_expired")
		}
	case time.Time:
		if time.Now().After(v) {
			return fmt.Errorf("plan_expired")
		}
	}
	return nil
}
