<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = new mysqli('localhost', 'root', '', 'user_management');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['registration'])) {
    $firstname = isset($_POST['firstname']) ? htmlspecialchars($_POST['firstname']) : null;
    $lastname = isset($_POST['lastname']) ? htmlspecialchars($_POST['lastname']) : null;
    $email = isset($_POST['email']) ? filter_var($_POST['email'], FILTER_SANITIZE_EMAIL) : null;
    $password = isset($_POST['password']) ? $_POST['password'] : null;
    $mobile_no = isset($_POST['mobile_no']) ? htmlspecialchars($_POST['mobile_no']) : null;

    if ($firstname && $lastname && $email && $password && $mobile_no) {
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            die("Invalid email format.");
        }

        $email_check = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $email_check->bind_param("s", $email);
        $email_check->execute();
        $email_check->store_result();

        if ($email_check->num_rows > 0) {
            echo "Error: Email already registered.";
            $email_check->close();
            exit();
        }
        $email_check->close();

        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        $sql = "INSERT INTO users (firstname, lastname, email, password, mobile_no) VALUES (?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sssss", $firstname, $lastname, $email, $hashed_password, $mobile_no);

        if ($stmt->execute()) {
            
            header("Location: comparison.html");
            exit();
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    } else {
        echo "Please fill in all fields.";
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['contact'])) {
    
    $name = isset($_POST['name']) ? htmlspecialchars($_POST['name']) : null;
    $contact_email = isset($_POST['contact_email']) ? filter_var($_POST['contact_email'], FILTER_SANITIZE_EMAIL) : null;
    $message = isset($_POST['message']) ? htmlspecialchars($_POST['message']) : null;

    if ($name && $contact_email && $message) {
        
        if (!filter_var($contact_email, FILTER_VALIDATE_EMAIL)) {
            die("Invalid email format.");
        }

        $sql = "INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sss", $name, $contact_email, $message);

        if ($stmt->execute()) {
            header("Location: home.html");
            exit();
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    } else {
        echo "Please fill in all fields.";
    }
}

$conn->close();
?>
