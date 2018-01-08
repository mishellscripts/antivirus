<?php

require_once 'common_functions.php';
require_once 'login.php';

// Start MySQL connection
$conn = new mysqli($hn, $un, $pw, $db);
if ($conn->connect_error) die("<p class='error'>Sorry! Encountered a connection error. Please try again another time.</p>");    

// Require admin log in
if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW'])) {
    reauthenticate("Please enter your username and password.");
}

// Sanitize username and password input
$temp_un = sanitizeMySQL($conn, $_SERVER['PHP_AUTH_USER']);
$temp_pw = sanitizeMySQL($conn, $_SERVER['PHP_AUTH_PW']);

// Compare sanitized username with username in database
$query = "SELECT * FROM admin WHERE username='$temp_un'";
$result = $conn->query($query);
if (!$result) reauthenticate("Incorrect username/password combination.");
elseif ($result->num_rows) {

    // If admin user exists, check that password matches after hashing the salted password
    $row = $result->fetch_array(MYSQLI_NUM);
    $result->close();

    // Salt and hash the password
    $salt1 = "qm&h*";
    $salt2 = "pg!@";
    $token = hash('ripemd128', "$salt1$temp_pw$salt2");
    
    if ($token == $row[1]) {
        // Once authenticated, start the session and set session information
        session_start();
        session_regenerate_id();
        $_SESSION['username'] = $temp_un;
        $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
        $_SESSION['timeout'] = time();

        die("Hi, you are now logged in as '$row[0]'<p><a href='admin.php'>Click here to continue</a></p>");
    } else {
        reauthenticate("Invalid username/password combination.");
    }
} else {
    reauthenticate("Invalid username/password combination.");
}

// Close the MySQL connection and resources once not needed
$result-> close();
$conn->close();


/**
 * When authentication fails, provides another chance to the admin to reenter their username/password credentials
 * Displays prompt again and updates the error message to provided error message when admin clicks the 'Cancel' button
 * @param $message the error message to display on cancel
 */
 function reauthenticate($message) {
    // Erase server variables if admin tried to log in with wrong credentials
    if (isset($_SERVER)) $_SERVER = array();
    // Display prompt
    header('WWW-Authenticate: Basic realm="Restricted Section"');
    header('HTTP/1.0 401 Unauthorized');
    // Terminate script execution and update error message if admin clicks 'Cancel' button
    die($message);
}

?>