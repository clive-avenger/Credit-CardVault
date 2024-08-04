<?php
session_start();

// Database configuration
$host = 'localhost';
$db = 'creditcardvault';
$user = 'root';
$password = '';

// Create a new PDO instance
try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("ERROR: Could not connect. " . $e->getMessage());
}

$error = '';

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Hash the password using SHA-256
    $hashed_password = hash('sha256', $password);

    // Prepare a select statement
    $sql = "SELECT * FROM Users WHERE Username = :username AND Password = :password";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->bindParam(':password', $hashed_password, PDO::PARAM_STR);

    // Execute the statement
    $stmt->execute();

    // Check if the user exists
    if ($stmt->rowCount() == 1) {
        $user = $stmt->fetch();
        $_SESSION['user_id'] = $user['UserID'];
        $_SESSION['role'] = $user['Role'];
        header("Location: index.php?action=dashboard");
        exit;
    } else {
        $error = "Invalid username or password.";
    }
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] == 'logout') {
    session_destroy();
    header("Location: index.php");
    exit;
}
?>
