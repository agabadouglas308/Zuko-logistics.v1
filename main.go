package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

//go:embed index.html
var htmlContent embed.FS

// ----------------------------
// JWT Configuration
// ----------------------------
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func init() {
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("default-dev-secret")
		log.Println("⚠️  WARNING: Using default JWT_SECRET. Set it in environment for production.")
	}
}

// Claims structure
type Claims struct {
	Username string `json:"username"`
	UserID   int    `json:"user_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// ----------------------------
// Database setup (with users table)
// ----------------------------
func initDB(db *sql.DB) error {
	itemsTable := `
	CREATE TABLE IF NOT EXISTS items (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		stock_level INTEGER NOT NULL,
		reorder_point INTEGER NOT NULL
	);`
	if _, err := db.Exec(itemsTable); err != nil {
		return fmt.Errorf("failed to create items table: %w", err)
	}

	ordersTable := `
	CREATE TABLE IF NOT EXISTS purchase_orders (
		id TEXT PRIMARY KEY,
		item_id TEXT NOT NULL,
		item_name TEXT NOT NULL,
		quantity INTEGER NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`
	if _, err := db.Exec(ordersTable); err != nil {
		return fmt.Errorf("failed to create orders table: %w", err)
	}

	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(usersTable); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	fmt.Println("✅ Database tables verified/created.")
	return nil
}

// Seed default admin
func seedAdmin(db *sql.DB) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		fmt.Println("✅ Admin user already exists.")
		return nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	_, err = db.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
		"admin", string(hashedPassword), "admin",
	)
	if err != nil {
		return fmt.Errorf("failed to seed admin: %w", err)
	}
	fmt.Println("✅ Admin user created (username: admin, password: admin123)")
	return nil
}

func seedItems(db *sql.DB) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM items").Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		fmt.Println("✅ Items already seeded. Skipping.")
		return nil
	}

	_, err = db.Exec(`
		INSERT INTO items (id, name, stock_level, reorder_point)
		VALUES
			('AMMO-556', '5.56mm Ammo Crate', 100, 50),
			('FOOD-MRE', 'Meal Ready-to-Eat (MRE)', 500, 200),
			('MED-TOUR', 'Tourniquet Kit', 25, 10)
	`)
	if err != nil {
		return fmt.Errorf("failed to seed items: %w", err)
	}
	fmt.Println("✅ Seeded default inventory items.")
	return nil
}

// ----------------------------
// User functions
// ----------------------------
func getUserByUsername(db *sql.DB, username string) (id int, passwordHash string, role string, err error) {
	err = db.QueryRow(
		"SELECT id, password_hash, role FROM users WHERE username = $1",
		username,
	).Scan(&id, &passwordHash, &role)
	if err == sql.ErrNoRows {
		return 0, "", "", nil
	}
	if err != nil {
		return 0, "", "", err
	}
	return id, passwordHash, role, nil
}

func createUser(db *sql.DB, username, password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		"INSERT INTO users (username, password_hash) VALUES ($1, $2)",
		username, string(hashed),
	)
	return err
}

// ----------------------------
// Handlers
// ----------------------------
func handleRegister(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if len(creds.Username) < 3 || len(creds.Password) < 6 {
			http.Error(w, "Username must be at least 3 chars, password at least 6", http.StatusBadRequest)
			return
		}

		err := createUser(db, creds.Username, creds.Password)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				http.Error(w, "Username already taken", http.StatusConflict)
			} else {
				http.Error(w, "Failed to create user", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
	}
}

func handleLogin(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		userID, hashedPassword, role, err := getUserByUsername(db, creds.Username)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		if userID == 0 {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password)); err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		expiration := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			Username: creds.Username,
			UserID:   userID,
			Role:     role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expiration),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "aegislog",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

// ----------------------------
// JWT Middleware (now checks user existence in DB)
// ----------------------------
func jwtMiddleware(db *sql.DB, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			http.Error(w, "Invalid Authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[len(prefix):]
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// --- NEW: Check if user still exists in the database ---
		var exists bool
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", claims.Username).Scan(&exists)
		if err != nil {
			log.Printf("Error checking user existence: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "User no longer exists", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// ----------------------------
// Inventory Module (unchanged)
// ----------------------------
type InventoryDB struct {
	db *sql.DB
}

func (inv *InventoryDB) UpdateStock(id string, quantity int, orderChan chan PurchaseOrder) bool {
	tx, err := inv.db.Begin()
	if err != nil {
		log.Println("Failed to begin transaction:", err)
		return false
	}
	defer tx.Rollback()

	var currentStock, reorderPoint int
	err = tx.QueryRow(
		"SELECT stock_level, reorder_point FROM items WHERE id = $1 FOR UPDATE",
		id,
	).Scan(&currentStock, &reorderPoint)
	if err == sql.ErrNoRows {
		log.Printf("Item %s not found", id)
		return false
	}
	if err != nil {
		log.Println("Database error:", err)
		return false
	}

	newStock := currentStock + quantity
	if newStock < 0 {
		log.Printf("Insufficient stock for %s: current %d, request %d", id, currentStock, quantity)
		return false
	}

	_, err = tx.Exec("UPDATE items SET stock_level = $1 WHERE id = $2", newStock, id)
	if err != nil {
		log.Println("Failed to update stock:", err)
		return false
	}

	if err := tx.Commit(); err != nil {
		log.Println("Failed to commit transaction:", err)
		return false
	}

	if newStock <= reorderPoint {
		var itemName string
		inv.db.QueryRow("SELECT name FROM items WHERE id = $1", id).Scan(&itemName)

		order := PurchaseOrder{
			ID:        fmt.Sprintf("PO-%d", time.Now().UnixNano()),
			ItemID:    id,
			ItemName:  itemName,
			Quantity:  reorderPoint * 2,
			Status:    "PENDING",
			CreatedAt: time.Now(),
		}
		select {
		case orderChan <- order:
			fmt.Printf("📦 [INVENTORY] Auto-order placed for %s (Qty: %d)\n", itemName, order.Quantity)
		default:
			fmt.Println("⚠️  [INVENTORY] Procurement channel full, order dropped!")
		}
	}
	return true
}

func (inv *InventoryDB) GetAllItems() ([]Item, error) {
	rows, err := inv.db.Query("SELECT id, name, stock_level, reorder_point FROM items ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var i Item
		if err := rows.Scan(&i.ID, &i.Name, &i.StockLevel, &i.ReorderPoint); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	return items, nil
}

func (inv *InventoryDB) GetItemByID(id string) (*Item, error) {
	var i Item
	err := inv.db.QueryRow("SELECT id, name, stock_level, reorder_point FROM items WHERE id = $1", id).
		Scan(&i.ID, &i.Name, &i.StockLevel, &i.ReorderPoint)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

func (inv *InventoryDB) DisplayAllItems() {
	rows, err := inv.db.Query("SELECT id, name, stock_level, reorder_point FROM items ORDER BY id")
	if err != nil {
		log.Println("Failed to query items:", err)
		return
	}
	defer rows.Close()

	fmt.Println("\n=== WAREHOUSE INVENTORY ===")
	fmt.Printf("%-15s | %-30s | %-10s | %-10s\n", "ID", "Name", "Stock", "Reorder")
	fmt.Println("------------------------------------------------------------")
	for rows.Next() {
		var id, name string
		var stock, reorder int
		if err := rows.Scan(&id, &name, &stock, &reorder); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		fmt.Printf("%-15s | %-30s | %-10d | %-10d\n", id, name, stock, reorder)
	}
	fmt.Println("------------------------------------------------------------")
}

// ----------------------------
// Procurement Module (unchanged)
// ----------------------------
type PurchaseOrder struct {
	ID        string    `json:"id"`
	ItemID    string    `json:"item_id"`
	ItemName  string    `json:"item_name"`
	Quantity  int       `json:"quantity"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type ProcurementDB struct {
	db *sql.DB
}

func NewProcurementDB(db *sql.DB, orderChan chan PurchaseOrder) *ProcurementDB {
	ps := &ProcurementDB{db: db}
	go ps.processOrders(orderChan)
	return ps
}

func (ps *ProcurementDB) processOrders(orderChan chan PurchaseOrder) {
	for order := range orderChan {
		time.Sleep(1 * time.Second)
		order.Status = "APPROVED"

		_, err := ps.db.Exec(
			"INSERT INTO purchase_orders (id, item_id, item_name, quantity, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
			order.ID, order.ItemID, order.ItemName, order.Quantity, order.Status, order.CreatedAt,
		)
		if err != nil {
			log.Printf("Failed to save order %s: %v", order.ID, err)
		} else {
			fmt.Printf("📋 [PROCUREMENT] Order %s APPROVED: %d units of %s\n", order.ID, order.Quantity, order.ItemName)
		}
	}
}

func (ps *ProcurementDB) GetRecentOrders(limit int) ([]PurchaseOrder, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := ps.db.Query(
		"SELECT id, item_id, item_name, quantity, status, created_at FROM purchase_orders ORDER BY created_at DESC LIMIT $1",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orders []PurchaseOrder
	for rows.Next() {
		var o PurchaseOrder
		if err := rows.Scan(&o.ID, &o.ItemID, &o.ItemName, &o.Quantity, &o.Status, &o.CreatedAt); err != nil {
			return nil, err
		}
		orders = append(orders, o)
	}
	return orders, nil
}

func (ps *ProcurementDB) GetOrderByID(id string) (*PurchaseOrder, error) {
	var o PurchaseOrder
	err := ps.db.QueryRow(
		"SELECT id, item_id, item_name, quantity, status, created_at FROM purchase_orders WHERE id = $1",
		id,
	).Scan(&o.ID, &o.ItemID, &o.ItemName, &o.Quantity, &o.Status, &o.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (ps *ProcurementDB) ReceiveOrder(orderID string) error {
	tx, err := ps.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	var itemID string
	var quantity int
	var status string
	err = tx.QueryRow(
		"SELECT item_id, quantity, status FROM purchase_orders WHERE id = $1 FOR UPDATE",
		orderID,
	).Scan(&itemID, &quantity, &status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("order %s not found", orderID)
	}
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if status == "RECEIVED" {
		return fmt.Errorf("order %s already received", orderID)
	}

	var currentStock int
	err = tx.QueryRow(
		"SELECT stock_level FROM items WHERE id = $1 FOR UPDATE",
		itemID,
	).Scan(&currentStock)
	if err != nil {
		return fmt.Errorf("item %s not found", itemID)
	}

	newStock := currentStock + quantity
	_, err = tx.Exec(
		"UPDATE items SET stock_level = $1 WHERE id = $2",
		newStock, itemID,
	)
	if err != nil {
		return fmt.Errorf("failed to update stock: %w", err)
	}

	_, err = tx.Exec(
		"UPDATE purchase_orders SET status = 'RECEIVED' WHERE id = $1",
		orderID,
	)
	if err != nil {
		return fmt.Errorf("failed to update order status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	fmt.Printf("📦 [RECEIVE] Order %s received. Added %d units to %s. New stock: %d\n",
		orderID, quantity, itemID, newStock)
	return nil
}

// ----------------------------
// Predictive Maintenance (unchanged)
// ----------------------------
type Equipment struct {
	ID          string
	Name        string
	HealthScore int
}

type MaintenanceAlert struct {
	EquipmentID   string `json:"equipment_id"`
	EquipmentName string `json:"equipment_name"`
	HealthScore   int    `json:"health_score"`
	Message       string `json:"message"`
	Timestamp     string `json:"timestamp"`
}

func monitorEquipment(equip Equipment, alertChannel chan MaintenanceAlert) {
	localEquip := equip
	for {
		sleepTime := time.Duration(2+rand.Intn(4)) * time.Second
		time.Sleep(sleepTime)

		degradation := rand.Intn(5) + 1
		localEquip.HealthScore -= degradation
		if localEquip.HealthScore < 0 {
			localEquip.HealthScore = 0
		}

		if localEquip.HealthScore <= 30 {
			alertChannel <- MaintenanceAlert{
				EquipmentID:   localEquip.ID,
				EquipmentName: localEquip.Name,
				HealthScore:   localEquip.HealthScore,
				Message:       fmt.Sprintf("⚠️ %s needs maintenance!", localEquip.Name),
				Timestamp:     time.Now().Format("15:04:05"),
			}
		}

		if localEquip.HealthScore == 0 {
			alertChannel <- MaintenanceAlert{
				EquipmentID:   localEquip.ID,
				EquipmentName: localEquip.Name,
				HealthScore:   0,
				Message:       fmt.Sprintf("💀 %s has FAILED!", localEquip.Name),
				Timestamp:     time.Now().Format("15:04:05"),
			}
			return
		}
	}
}

// ----------------------------
// WebSocket Hub (unchanged)
// ----------------------------
var (
	clients   = make(map[*websocket.Conn]bool)
	broadcast = make(chan MaintenanceAlert)
	mu        sync.Mutex
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("WebSocket upgrade failed:", err)
		return
	}
	mu.Lock()
	clients[conn] = true
	mu.Unlock()

	log.Printf("📡 New WebSocket client connected. Total: %d", len(clients))

	defer func() {
		mu.Lock()
		delete(clients, conn)
		mu.Unlock()
		conn.Close()
		log.Printf("📡 Client disconnected. Total: %d", len(clients))
	}()

	for {
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}
}

func broadcastAlerts() {
	for alert := range broadcast {
		jsonData, err := json.Marshal(alert)
		if err != nil {
			log.Println("Failed to marshal alert:", err)
			continue
		}

		mu.Lock()
		for conn := range clients {
			err := conn.WriteMessage(websocket.TextMessage, jsonData)
			if err != nil {
				conn.Close()
				delete(clients, conn)
			}
		}
		mu.Unlock()
	}
}

// ----------------------------
// REST API Handlers
// ----------------------------
type Item struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	StockLevel   int    `json:"stock_level"`
	ReorderPoint int    `json:"reorder_point"`
}

type AdjustRequest struct {
	Quantity int `json:"quantity"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Public GET handlers
func handleGetItems(inv *InventoryDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := inv.GetAllItems()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(items)
	}
}

func handleGetItem(inv *InventoryDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing item ID"})
			return
		}
		id := pathParts[3]

		item, err := inv.GetItemByID(id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}
		if item == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Item not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(item)
	}
}

func handleGetOrders(proc *ProcurementDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orders, err := proc.GetRecentOrders(10)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(orders)
	}
}

// Protected POST handlers (with JWT)
func handleAdjustStock(inv *InventoryDB, orderChan chan PurchaseOrder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed"})
			return
		}

		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 5 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing item ID"})
			return
		}
		id := pathParts[3]

		var req AdjustRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON body"})
			return
		}

		success := inv.UpdateStock(id, req.Quantity, orderChan)
		if !success {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Update failed (item not found or stock would go negative)"})
			return
		}

		item, _ := inv.GetItemByID(id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(item)
	}
}

func handleReceiveOrder(proc *ProcurementDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed"})
			return
		}

		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 5 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing order ID"})
			return
		}
		orderID := pathParts[3]

		err := proc.ReceiveOrder(orderID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}

		order, _ := proc.GetOrderByID(orderID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(order)
	}
}

// ----------------------------
// Main
// ----------------------------
func main() {
	rand.Seed(time.Now().UnixNano())

	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://aegis_user:aegis123@localhost:5432/aegislog?sslmode=disable"
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal("Failed to open database connection:", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal("Cannot ping database:", err)
	}
	fmt.Println("🔌 Connected to PostgreSQL successfully.")

	if err := initDB(db); err != nil {
		log.Fatal("DB initialization failed:", err)
	}
	if err := seedAdmin(db); err != nil {
		log.Fatal("Admin seeding failed:", err)
	}
	if err := seedItems(db); err != nil {
		log.Fatal("Seeding failed:", err)
	}

	orderChannel := make(chan PurchaseOrder, 10)
	procurement := NewProcurementDB(db, orderChannel)
	inventory := &InventoryDB{db: db}

	// Start maintenance monitors
	alertChannel := make(chan MaintenanceAlert)
	equipmentList := []Equipment{
		{ID: "GEN-001", Name: "Diesel Generator", HealthScore: 85},
		{ID: "TRK-007", Name: "Supply Truck", HealthScore: 65},
		{ID: "RAD-011", Name: "Long-Range Radar", HealthScore: 45},
	}
	for _, equip := range equipmentList {
		go monitorEquipment(equip, alertChannel)
		fmt.Printf("📡 Monitoring: %s (Health: %d)\n", equip.Name, equip.HealthScore)
	}

	go func() {
		for alert := range alertChannel {
			broadcast <- alert
		}
	}()
	go broadcastAlerts()

	// Simulation: consume stock every 8 seconds
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			consumed := rand.Intn(25) + 5
			fmt.Printf("\n🔫 [SIMULATION] Consuming %d rounds of AMMO-556...\n", consumed)
			success := inventory.UpdateStock("AMMO-556", -consumed, orderChannel)
			if success {
				inventory.DisplayAllItems()
			} else {
				fmt.Println("❌ Failed to consume stock.")
			}
		}
	}()

	// HTTP routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		htmlFile, err := htmlContent.ReadFile("index.html")
		if err != nil {
			http.Error(w, "Index page not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(htmlFile)
	})
	http.HandleFunc("/ws", handleWebSocket)

	// Public endpoints (GET + login/register)
	http.HandleFunc("GET /api/items", handleGetItems(inventory))
	http.HandleFunc("GET /api/items/{id}", handleGetItem(inventory))
	http.HandleFunc("GET /api/orders", handleGetOrders(procurement))

	http.HandleFunc("/api/register", handleRegister(db))
	http.HandleFunc("/api/login", handleLogin(db))

	// Protected POST endpoints (JWT required) – pass db to middleware
	http.HandleFunc("POST /api/items/{id}/adjust", jwtMiddleware(db, handleAdjustStock(inventory, orderChannel)))
	http.HandleFunc("POST /api/orders/{id}/receive", jwtMiddleware(db, handleReceiveOrder(procurement)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("\n🚀 AegisLog Web Server running at http://localhost:%s\n", port)
	fmt.Println("📲 WebSocket alerts: ws://localhost/ws")
	fmt.Println("🔒 Protected endpoints require JWT (login via /api/login)")
	fmt.Println("📝 Registration endpoint: /api/register")
	fmt.Println("Press Ctrl+C to stop.\n")

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
