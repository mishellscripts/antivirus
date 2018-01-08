<?php

/**
 * Given a file, determines if the file is valid
 * Checks for file existence and .txt extension
 * @param $file the file array to check
 */
function is_file_valid($file) {
    // Check #1 - Check that the file exists
    if (!file_exists($file['tmp_name'])) {
        // Validation failed - file not uploaded. Display error message
        return "No file has been uploaded. Try again.<br>";
    }
    // Check #2 - Validate that the file type is a text file with .txt extension
    elseif ($file['type'] != "text/plain") {
        // Validation failed - file not txt. Display error message
        return "Only files with .txt extension are accepted.<br>";
    }
    // Return empty string indicating no errors on validation success
    return "";
}

/**
 * Sanitize string, getting rid of unwanted slashes and removing HTML
 * From Lecture 17 - PHP HTML (Slide 37)
 */
function sanitizeString($string) {
    $string = stripslashes($string);
    $string = strip_tags($string);
    $string = htmlentities($string);
    return $string;
}

/**
 * Sanitize string, preventing SQL injection and getting rid of unwanted slashes and removing HTML
 * From Lecture 17 - PHP HTML (Slide 37)
 */
function sanitizeMySQL($conn, $string) {
    $string = $conn->real_escape_string($string);
    $string = sanitizeString($string);
    return $string;
}

?>