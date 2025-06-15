package main

import (
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func main() {
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	logrus.Info("Starting Bank API Service...")

	InitStorage()
	logrus.Info("In-memory storage initialized")

	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/register", RegisterUserHandler).Methods("POST")
	r.HandleFunc("/login", LoginUserHandler).Methods("POST")

	// Protected routes
	authRouter := r.PathPrefix("/").Subrouter()
	authRouter.Use(AuthMiddleware)

	authRouter.HandleFunc("/accounts", CreateAccountHandler).Methods("POST")
	authRouter.HandleFunc("/users/{userId}/accounts", GetUserAccountsHandler).Methods("GET")
	authRouter.HandleFunc("/cards", GenerateCardHandler).Methods("POST")
	authRouter.HandleFunc("/accounts/{accountId}/cards", GetAccountCardsHandler).Methods("GET")
	authRouter.HandleFunc("/payments/card", PayWithCardHandler).Methods("POST")
	authRouter.HandleFunc("/transfers", TransferHandler).Methods("POST")
	authRouter.HandleFunc("/deposits", DepositHandler).Methods("POST")
	authRouter.HandleFunc("/loans", ApplyLoanHandler).Methods("POST")
	authRouter.HandleFunc("/loans/{loanId}/schedule", GetLoanScheduleHandler).Methods("GET")
	authRouter.HandleFunc("/analytics/transactions/{accountId}", GetTransactionsHandler).Methods("GET")
	authRouter.HandleFunc("/analytics/summary/{userId}", GetFinancialSummaryHandler).Methods("GET")
	authRouter.HandleFunc("/accounts/{accountId}/predict", PredictBalanceHandler).Methods("GET")

	// Start scheduler
	go StartPaymentScheduler(12 * time.Hour)

	port := "8080"
	logrus.Infof("Server starting on port %s", port)
	logrus.Fatal(http.ListenAndServe(":"+port, loggingMiddleware(r)))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"ip":     r.RemoteAddr,
		}).Info("Request started")

		next.ServeHTTP(w, r)

		logrus.WithFields(logrus.Fields{
			"duration": time.Since(start),
			"method":   r.Method,
			"path":     r.URL.Path,
		}).Info("Request completed")
	})
}
