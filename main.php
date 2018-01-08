<?php

require_once 'common_functions.php';
require_once 'login.php';

// Display the file upload form HTML
echo <<<_END
<html>
    <head>
        <title>Virus Scanner</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="content">    
            <h1>VIRUS SCANNER</h1>
                <p>Check a file against malware by uploading it to be scanned.</p>            
                <form method="post" action="main.php" enctype="multipart/form-data">
_END;

// MySQL connection
$conn = new mysqli($hn, $un, $pw, $db);
if($conn->connect_error) die("<p class='error'>Sorry! Encountered a connection error. Please try again another time.</p>");    

// Print the remainder of the form only if the database connection is successful
echo <<<_END
                <p><input type="file" name="file"></p>
                <input id="upload" type="submit" value="Upload">
            </form>
        <hr>
        <p>Output:</p>
_END;

// Check if a file has been uploaded
if ($_FILES) {
    // Store check result of file validation
    $error = is_file_valid($_FILES['file']);
    // Proceed to check malware if there is no error message from check result
    if ($error == "") {
        if (check_file_is_infected($conn, $_FILES['file']['tmp_name'])) {
            echo "<p class='error'>This file is marked as infected and containing malware.</p>";
        } else {
            echo "<p class='success'>Clean - We did not detect any malware in this file.</p>";
        }
    } else {
        echo "<p class='error'>$error</p>";
    }
}

// Display proper closing HTML tags
echo "</div></body></html>";


/**
 * Handles file upload by retrieving the contents and modifying database
 * @param $conn the connection mysql object
 * @param $path   the file path of the file uploaded
*/
function check_file_is_infected($conn, $path) {

    // Get and sanitize file contents
    $file_content = file_get_contents($path);
    $file_content = sanitizeMySQL($conn, $file_content);

    // Get all signatures to check file against from db
    $query = "SELECT signature FROM malware";
    $result = $conn->query($query);
    if (!$result) die ("<p class='error'>Scan failed. Please try again another time.</p>");

    $rows = $result->num_rows;
    // For each signature, check if the file content contains the signature anywhere in the file
    for ($i = 0; $i < $rows; $i++) {
        $result->data_seek($i);
        $row = $result->fetch_array(MYSQLI_NUM);
        // Once match is found, return result indicating file is infected
        if (strpos($file_content, $row[0]) !== false) return true;
    }

    // Close the connection
    $conn->close();
    
    // When all checks are passed, return result indicating that the file is not infected
    return false;
}

?>