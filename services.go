package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/shopspring/decimal"
	"gopkg.in/mail.v2"
)

const (
	// Демо-ключи (ЗАМЕНИТЕ НА РЕАЛЬНЫЕ В ПРОДАКШЕНЕ!)
	encryptionKeyStr = "my_32_byte_encryption_key_1234567890" // 32 байта
	hmacKeyStr       = "my_hmac_secret_key_1234567890"
	cbrURL           = "https://www.cbr.ru/DailyInfoWebServ/DailyInfo.asmx"
)

var (
	encryptionKey = []byte(encryptionKeyStr)
	hmacKey       = []byte(hmacKeyStr)
)

func buildSOAPRequest() string {
	fromDate := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	toDate := time.Now().Format("2006-01-02")
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
	<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
		<soap12:Body>
			<KeyRate xmlns="http://web.cbr.ru/">
				<fromDate>%s</fromDate>
				<ToDate>%s</ToDate>
			</KeyRate>
		</soap12:Body>
	</soap12:Envelope>`, fromDate, toDate)
}

func sendSOAPRequest(soapRequest string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(
		"POST",
		cbrURL,
		bytes.NewBuffer([]byte(soapRequest)),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://web.cbr.ru/KeyRate")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func parseXMLResponse(rawBody []byte) (float64, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawBody); err != nil {
		return 0, fmt.Errorf("XML parsing error: %v", err)
	}

	keyRateResults := doc.FindElements("//KeyRateResult")
	if len(keyRateResults) == 0 {
		return 0, errors.New("key rate data not found")
	}

	latestResult := keyRateResults[len(keyRateResults)-1]

	rateElement := latestResult.FindElement("Rate")
	if rateElement == nil {
		return 0, errors.New("rate element not found")
	}

	rateStr := rateElement.Text()
	var rate float64
	if _, err := fmt.Sscanf(rateStr, "%f", &rate); err != nil {
		return 0, fmt.Errorf("rate conversion error: %v", err)
	}

	return rate, nil
}

func GetCBRKeyRate() (decimal.Decimal, error) {
	soapRequest := buildSOAPRequest()
	rawBody, err := sendSOAPRequest(soapRequest)
	if err != nil {
		return decimal.Zero, err
	}

	rate, err := parseXMLResponse(rawBody)
	if err != nil {
		return decimal.Zero, err
	}

	return decimal.NewFromFloat(rate).Add(decimal.NewFromInt(5)), nil
}

func SendEmailNotification(to, subject, body string) error {
	if os.Getenv("SMTP_DISABLED") == "true" {
		log.Printf("SMTP disabled. Skipping email to %s: %s", to, subject)
		return nil
	}

	m := mail.NewMessage()
	m.SetHeader("From", "noreply@bankapp.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := mail.NewDialer(
		os.Getenv("SMTP_HOST"),
		587,
		os.Getenv("SMTP_USER"),
		os.Getenv("SMTP_PASSWORD"),
	)
	d.TLSConfig = &tls.Config{ServerName: os.Getenv("SMTP_HOST")}

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Error sending email: %v", err)
		return err
	}

	log.Printf("Email sent to %s", to)
	return nil
}

func ComputeHMAC(data string) string {
	h := hmac.New(sha256.New, hmacKey)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

type ValCurs struct {
	XMLName xml.Name `xml:"ValCurs"`
	Date    string   `xml:"Date,attr"`
	Valute  []Valute `xml:"Valute"`
}

type Valute struct {
	XMLName  xml.Name `xml:"Valute"`
	ID       string   `xml:"ID,attr"`
	NumCode  string   `xml:"NumCode"`
	CharCode string   `xml:"CharCode"`
	Nominal  int      `xml:"Nominal"`
	Name     string   `xml:"Name"`
	Value    string   `xml:"Value"`
}

var cachedKeyRate struct {
	rate decimal.Decimal
	time time.Time
}
var keyRateMutex sync.Mutex

var smtpConfig = struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}{
	Host:     "smtp.example.com",
	Port:     587,
	Username: "your_email@example.com",
	Password: "your_password",
	From:     "bankapp@example.com",
}
