# BankApp REST API Простое банковское приложение на Go, позволяющее управлять пользователями, счетами, картами, транзакциями, кредитами и аналитикой. 

## 🛠 Технологии и стек 
- Язык программирования: Go (Golang) 
- API: RESTful 
- Маршрутизация: gorilla/mux
- Аутентификация: JWT (golang-jwt/jwt/v5)
- Логирование: logrus
- Шифрование: bcrypt, HMAC-SHA256, AES-GCM
- Работа с XML: beevik/etree
- Отправка email: gomail.v2
- Десятичные числа: shopspring/decimal
- Генерация UUID: google/uuid 

## 🚀 Функциональность 
1. Пользователи (Users) 
- Регистрация нового пользователя
- Аутентификация (логин) с выдачей JWT-токена
- Проверка уникальности email и username
2. Счета (Accounts)
- Создание нового счета
- Получение списка счетов пользователя
- Пополнение счета (депозит)
- Прогноз баланса на N дней
3. Карты (Cards)
- Генерация виртуальной карты (с валидным номером по алгоритму Луна)
- Получение списка карт по счету
- Оплата с использованием карты
4. Транзакции (Transfers) 
- Перевод средств между счетами
- Просмотр истории транзакций по счету
- Финансовая аналитика (статистика по доходам/расходам)
5. Кредиты (Loans)
- Оформление кредита с расчетом аннуитетных платежей
- Получение графика платежей
- Автоматическое списание платежей (шедулер)
6. Интеграции
- Получение ключевой ставки ЦБ РФ (через SOAP)
- Отправка email-уведомлений (SMTP)
7. Безопасность
- Шифрование данных карт (AES-GCM)
- Хеширование паролей и CVV (bcrypt)
- Проверка целостности данных (HMAC)
- Аутентификация и авторизация (JWT)


## 📌 Примеры запросов 
Регистрация пользователя 
- curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "securepassword"
  }'

 Аутентификация (получение токена)
 - curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "securepassword"
  }'

Создание счета (требуется токен)
- curl -X POST http://localhost:8080/accounts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ваш-jwt-токен>" \
  -d '{
    "user_id": "id-пользователя"
  }'

Генерация карты (требуется токен)
- curl -X POST http://localhost:8080/cards \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ваш-jwt-токен>" \
  -d '{
    "account_id": "id-счета"
  }'

Перевод средств (требуется токен)
- curl -X POST http://localhost:8080/transfers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ваш-jwt-токен>" \
  -d '{
    "from_account_id": "id-счета-отправителя",
    "to_account_id": "id-счета-получателя",
    "amount": 100.50
  }'

Оформление кредита (требуется токен)
- curl -X POST http://localhost:8080/loans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ваш-jwt-токен>" \
  -d '{
    "user_id": "id-пользователя",
    "account_id": "id-счета",
    "amount": 10000,
    "term_months": 12
  }'

