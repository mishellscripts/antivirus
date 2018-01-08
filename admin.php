<?php

require_once 'common_functions.php';
require_once 'login.php';

// Start MySQL connection
$conn = new mysqli($hn, $un, $pw, $db);
if ($conn->connect_error) die("<p class='error'>Sorry! Encountered a connection error. Please try again another time.</p>");    

// Add admin credentials to the database if doesn't exist already
$query = "SELECT * FROM admin";
$result = $conn->query($query);
if ($result->num_rows == 0) {
    add_admin($conn, $username, $password);
}

// Start the session
session_start();
session_regenerate_id();

// Store check result that session has not timed out - Duration of session is 24 hours
$timeout = isset($_SESSION['timeout']) && $_SESSION['timeout'] + 60*60*24 <= time();
// Store check result to prevent session hijacking - Ensure match of previous IP address and user agent string to current
$match = isset($_SESSION['check']) && $_SESSION['check'] == hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);

if (!(isset($_SESSION['username'])) || $timeout || !$match) {
    destroy_session_and_data();
    die("You're not logged in!<br><a href='authentication.php'>Click here to login</a>");
}

// Check if there exists an AJAX request to log out, ending the session
if (isset($_POST['function']) == "logout") {
    destroy_session_and_data();
}

// Display the file upload form HTML
echo <<<_END
<html>
    <head>
        <title>Virus Scanner</title>
        <link rel="stylesheet" href="style.css">
        <script src="validation.js"></script>
        <script>
        // Returns cross-browser supported Ajax request object
        function ajaxRequest() {
            // Non-IE browser
            try { var request = new XMLHttpRequest() } catch(e1) {
                // IE6+
                try { request = new ActiveXObject("Msxml2.XMLHTTP") } catch(e2) {
                    // IE5
                    try { request = new ActiveXObject("Microsoft.XMLHTTP") } catch(e3) {
                        // Browser does not support AJAX
                        request = false
                    }
                }
            }
            return request
        }
        
        // Opens a HTTP POST method to the admin to end the current session on logout
        function logOut() {
            // Send function parameter telling PHP what to do
            params = "function=logout"
            // Open HTTP POST method, handling request asynchronously (true)
            request = new ajaxRequest()
            request.open("POST", "admin.php", true)
            request.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
            //request.setRequestHeader("Content-length", params.length)
            //request.setRequestHeader("Connection", "close")
        
            // Define event handling callback function
            request.onreadystatechange = function() {
                if (this.readyState == 4) {
                    if (this.status == 200) {
                        // Reload the page on POST succcess
                        if (this.responseText != null) location.reload()
                        else alert("Ajax error: No data received")
                    } else {
                        alert("Ajax error: " + this.statusText)
                    }
                }
            }
            request.send(params)
        }
        </script>
        <nav>
            <button id="logout" onclick="logOut();">Logout</button>
        </nav>
    </head>
    <body>
        <div class="content">
            <h1>VIRUS SCANNER</h1>
            <p>Upload a surely infected file to add malware information to the database.</p>
            <form method="post" action="admin.php" onsubmit="validate(this);" enctype="multipart/form-data"">
                <p>
                    <label for="malware_name">Name:</label>
                    <input type="text" name="malware_name">
                </p>
                <p>
                    <label for="file">File upload:</label>
                    <input type="file" name="file">
                </p>
                <input id="upload" type="submit" value="Upload">
            </form>
            <hr>
            <p>Output:</p>
_END;

// Check if a file has been uploaded
if ($_FILES) {
    // Store check result of file validation
    $error = is_file_valid($_FILES['file']);
    // Proceed to add malware if there is no error message from check result
    if ($error == "") {
        add_malware($conn, $_POST['malware_name'], $_FILES['file']['tmp_name']);
    } else {
        echo "<p class='error'>$error</p>";
    }
}

// Close the MySQL connection and resources once not needed
$result->close();
$conn->close();

// Display proper closing HTML tags
echo "</div></body></html>";


/**
 * Validates name of file upload
 * Trims the name string and checks that the name is not an empty string and contains only letters, digits, _, -
 * @param $name the name of the malware file uploaded
 */
function validate_name($name) {
    $name = trim($name);

    // Check #1 - Name cannot be an empty string
    if ($name == "") return "Name for malware cannot be empty.";

    // Check #2 - Name contains only english letters (case insensitive), digits, _, -
    elseif (preg_match("/[^a-zA-Z0-9_-]/", $name)) 
        return "Only letters, digits, -, and _ are allowed in a username.<br>";
    
    // Checks passed - Return empty string indicating no error
    return "";
}

/**
 * Handles file upload by retrieving the file signature and inserting the file signature (first 20 bytes) into the database
 * @param $conn the connection mysql object
 * @param $name the name inputted by the admin
 * @param $path the file path of the malware file uploaded
 */
function add_malware($conn, $name, $path) {

    // Sanitize name input
    $name = sanitizeMySQL($conn, $name);
  
    // Perform PHP validation for file name
    $error = validate_name($name);

    // Terminate script execution on PHP validation fail and display generated error messages
    if ($error != "") die("<p class='error'>$error<p>");

    $fh = fopen($path, "r") or die("<p class='error'>Cannot open file. File does not exist or lacking permissions to open it.</p>");

    // Get the first 20 bytes (signature) of the file
    // If file size is less than 20, gets the whole file as the signature
    $signature = fread($fh, 20);

    // Sanitize the retrieved signature
    $signature = sanitizeMySQL($conn, $signature);

    // Check #1 - Malware file is not empty
    if (strlen($signature) == 0) die("<p class='error'>File contents cannot be empty.</p>");

    // Check #2 - Malware does not exist in database
    // Conditions used for checking for existence (equality):
    //  - There can be entries with the same malware name but different signature - The two entries are NOT equal
    //  - Malware entries are equal only when both name AND signature are equal

    $query = "SELECT * FROM malware WHERE name='$name' AND signature='$signature'";
    $result = $conn->query($query);

    if ($result->num_rows > 0) die("<p class='error'>This malware already exists in the database.</p>");

    // Checks passed - Insert sanitized file name and signature into database
    $query = "INSERT INTO malware VALUES('$name', '$signature')";
    $result = $conn->query($query);
    if (!$result) die ("<p class='error'>Database malware insert failed: " . $conn->error . "</p>");
    
    echo "<p class='success'>Success! Malware named '$name' has been added to the database.</p>";

    // Close the file handler
    fclose($fh);
}

/**
 * Adds admin credentials to the database after salting the password and hashing the result
 * @param $conn the connection mysql object
 * @param $un   the username of admin to add
 * @param $pw   the password of admin to add
 */
function add_admin($conn, $un, $pw) {
    // Sanitize the username and password
    $un = sanitizeMySQL($conn, $un);
    $pw = sanitizeMySQL($conn, $pw);

    // Salt the password
    $salt1 = "qm&h*";
    $salt2 = "pg!@";

    // Hash the password
    $token = hash('ripemd128', "$salt1$pw$salt2");

    // Insert the username and the hash of the salted password into admin
    $query = "INSERT INTO admin VALUES('$un', '$token')";
    $conn->query($query);
}

/**
 * Destroys a session and its data
 * From Lecture 19 - PHP - Sessions (Slide 13)
 */
function destroy_session_and_data() {
    // Erase session data
    $_SESSION = array();
    // Delete cookie by setting it to a time in the past
    setcookie(session_name(), '', time() - 2592000, '/');
    // Destroy the session
    session_destroy();
}

?>