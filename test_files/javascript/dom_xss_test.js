// Test cases for DOM XSS vulnerabilities

// Case 1: innerHTML with unsanitized input
function testInnerHTML(userInput) {
    const div = document.createElement('div');
    div.innerHTML = userInput; // Should trigger DOM XSS
}

// Case 2: document.write with concatenation
function testDocumentWrite(userInput) {
    document.write('<div>' + userInput + '</div>'); // Should trigger DOM XSS
}

// Case 3: insertAdjacentHTML with unsanitized input
function testInsertAdjacentHTML(userInput) {
    const div = document.createElement('div');
    div.insertAdjacentHTML('beforeend', userInput); // Should trigger DOM XSS
}

// Case 4: Safe usage with sanitization
function testSafeInnerHTML(userInput) {
    const div = document.createElement('div');
    div.innerHTML = DOMPurify.sanitize(userInput); // Should not trigger
}

// Case 5: Safe usage with textContent
function testSafeTextContent(userInput) {
    const div = document.createElement('div');
    div.textContent = userInput; // Should not trigger
} 