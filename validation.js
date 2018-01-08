/**
 * Validate form input, appending error message whenever errors are encountered
 * @param form the form object to check
 */
function validate(form) {
     // Check file name input, appending error message everytime a check fails
    error = validateName(form.malware_name.value)

    // Validation is successful if error messages were not appended (string is empty)
    if (error == "") { return true }
    
    // If validation of name fails, display generated error messages
    else { alert(error); return false }
}

/**
 * Validate name string, appending error message whenever errors are encountered
 * @param name the name to check
 */
function validateName(name) {
    name = name.trim()

    // Check #1 - Name cannot be an empty string
    if (name == "") return "Name for malware cannot be empty.\n"

    // Check #2 - Name contains only english letters (case insensitive), digits, _, -
    else if (/[^a-zA-Z0-9_-]/.test(name)) return "Only letters, digits, _, and - are allowed in a username.\n"

    // Checks passed - Return empty string indicating no error
    return "";
}