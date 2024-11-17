<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = new mysqli('localhost', 'root', '', 'user_management');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$login_input = $_POST['login_input'] ?? null; 
$password = $_POST['password'] ?? null;

if ($login_input && $password) {
    $stmt = $conn->prepare("SELECT password FROM users WHERE email = ? OR firstname = ?");
    $stmt->bind_param("ss", $login_input, $login_input);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        if (password_verify($password, $hashed_password)) {
           
            header("Location: comparison.html");
            exit();
        } else {
            echo "<script>alert('The username/email or password you entered is incorrect.'); window.location.href='login.html';</script>";
            exit();
        }
    } else {
       
        echo "<script>alert('The username/email or password you entered is incorrect.'); window.location.href='login.html';</script>";
        exit();
    }

    $stmt->close();
} else {
    echo "<script>alert('Both fields are required.'); window.location.href='login.html';</script>";
    exit();
}

$conn->close();
?>
