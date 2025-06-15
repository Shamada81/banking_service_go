package main

import (
	"time"

	"github.com/robfig/cron/v3"
	"github.com/shopspring/decimal"
	"github.com/sirupsen/logrus"
)

func StartPaymentScheduler(interval time.Duration) {
	c := cron.New()
	_, err := c.AddFunc("@every 12h", processDuePayments)
	if err != nil {
		logrus.Fatal("Failed to start scheduler:", err)
	}

	logrus.Info("Payment scheduler started")
	c.Run()
}

func processDuePayments() {
	logrus.Info("Processing due payments...")
	now := time.Now()

	for _, loan := range GetAllLoans() {
		for i, payment := range loan.PaymentSchedule {
			if !payment.Paid && payment.DueDate.Before(now) {
				account, ok := GetAccount(loan.AccountID)
				if !ok {
					logrus.Errorf("Account not found for loan %s", loan.ID)
					continue
				}

				if account.Balance.GreaterThanOrEqual(payment.Amount) {
					// Регулярный платеж
					_ = UpdateAccountBalance(account.ID, payment.Amount.Neg())
					payment.Paid = true
				} else {
					// Просрочка +10%
					penalty := payment.Amount.Mul(decimal.NewFromFloat(0.1))
					total := payment.Amount.Add(penalty)

					if account.Balance.GreaterThanOrEqual(total) {
						_ = UpdateAccountBalance(account.ID, total.Neg())
						payment.Paid = true
					}
				}

				// Обновляем график платежей
				loan.PaymentSchedule[i] = payment
				_ = UpdateLoan(loan)

				// Логируем и отправляем уведомление
				logrus.WithFields(logrus.Fields{
					"loan_id": loan.ID,
					"amount":  payment.Amount.String(),
				}).Info("Processed loan payment")
			}
		}
	}
}
