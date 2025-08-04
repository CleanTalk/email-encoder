To use the ContactsEncoder module:

// 1. Extend the platform-specific ContactsEncoder class
require_once 'path/to/ContactsEncoder.php';

class MyContactsEncoder extends ContactsEncoder {
    // You can override methods here if needed
}

// 2. Instantiate the encoder
$encoder = new MyContactsEncoder();

// 3. Prepare the content (HTML, text, etc.)
$content = '<p>Contact us at info@example.com</p>';

// 4. Encode contact details
$protectedContent = $encoder->modifyContent($content);

// 5. Output the modified content
echo $protectedContent;

