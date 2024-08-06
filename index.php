<?php
$pdo = new PDO('mysql:host=localhost;dbname=CreditCardVault', 'username', 'password');

$name = $_POST['name'];
$email = $_POST['email'];
$address = $_POST['address'];
$cardNumber = $_POST['cardNumber'];
$expiryDate = $_POST['expiryDate'];
$cvv = $_POST['cvv'];

$insertCustomer = $pdo->prepare("INSERT INTO Customers (Name, Email, Address) VALUES (?, ?, ?)");
$insertCustomer->execute([$name, $email, $address]);
$customerID = $pdo->lastInsertId();

$insertCard = $pdo->prepare("INSERT INTO CreditCards (CustomerID, CardNumber, ExpiryDate, CVV) VALUES (?, AES_ENCRYPT(?, 'secret_key'), AES_ENCRYPT(?, 'secret_key'), AES_ENCRYPT(?, 'secret_key'))");
$insertCard->execute([$customerID, $cardNumber, $expiryDate, $cvv]);

echo "Customer and card details stored successfully!";

// Insert credit card details
$insertCard = $pdo->prepare("INSERT INTO CreditCards (CustomerID, CardNumber, ExpiryDate, CVV) VALUES (?, AES_ENCRYPT(?, 'secret_key'), AES_ENCRYPT(?, 'secret_key'), AES_ENCRYPT(?, 'secret_key'))");
$insertCard->execute([$customerID, $cardNumber, $expiryDate, $cvv]);

// Retrieve credit card details
$getCard = $pdo->prepare("SELECT AES_DECRYPT(CardNumber, 'secret_key') AS CardNumber, AES_DECRYPT(ExpiryDate, 'secret_key') AS ExpiryDate, AES_DECRYPT(CVV, 'secret_key') AS CVV FROM CreditCards WHERE CustomerID = ?");
$getCard->execute([$customerID]);
$card = $getCard->fetch();

// Hash password
$passwordHash = hash('sha256', $password);

// Verify password
if (hash('sha256', $inputPassword) === $storedPasswordHash) {
    // Password is correct
}

?>
