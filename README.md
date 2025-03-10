### **Cross-Site Request Forgery (CSRF)**

**Cross-Site Request Forgery (CSRF)** is a type of security vulnerability that tricks a user into unknowingly submitting a malicious request from their browser to a web application where they are already authenticated. This attack can manipulate actions that the user is authorized to perform, such as changing account settings, making financial transactions, or sending messages, all without the user’s knowledge or consent.

CSRF exploits the trust a web application has in a user's browser, rather than exploiting weaknesses in the web application itself. Since browsers automatically include authentication cookies (like session IDs or JWT tokens) with every request, an attacker can leverage this behavior to perform actions on behalf of an authenticated user.

### **How CSRF Works**

1. **Victim’s Authentication**: The victim logs in to a website and obtains a session cookie that authenticates their identity. The session is stored in the victim’s browser.
   
2. **Malicious Action**: The attacker tricks the victim into clicking a link, loading an image, or submitting a form on a malicious website controlled by the attacker.

3. **Request Sent with Victim’s Cookies**: Since the victim is still authenticated on the legitimate website, the request made by the attacker’s crafted page is sent with the victim's authentication cookies. The web application trusts this request and processes it as if it were a legitimate action by the victim.

### **Example of a CSRF Attack**

Let's consider an online banking application where a user can transfer money by submitting a POST request to the following URL:

```
POST /transfer
```

The form requires the user to transfer money to a recipient, which is authorized by the user’s session.

#### **Vulnerable Code Example** (Banking Application):

```html
<form action="https://bank-website.com/transfer" method="POST">
    <input type="text" name="recipient" value="victim123">
    <input type="number" name="amount" value="1000">
    <input type="submit" value="Transfer">
</form>
```

This form allows the user to transfer money. An attacker can craft a similar form on their malicious website that submits the request on behalf of the user without their consent.

#### **Malicious Website (CSRF Attack)**:

```html
<!DOCTYPE html>
<html>
    <body>
        <h1>Special Offer</h1>
        <p>Click here for your discount!</p>
        <form action="https://bank-website.com/transfer" method="POST" style="display:none;">
            <input type="text" name="recipient" value="attacker456">
            <input type="number" name="amount" value="5000">
            <input type="submit">
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

When the victim visits the attacker’s website, the malicious form is automatically submitted, transferring money from the victim’s bank account to the attacker’s account. The victim's browser sends the request with their authentication cookies, and the server processes the request as if it were initiated by the user.

### **Consequences of CSRF**

1. **Unintended Actions**: An attacker can force a user to perform unintended actions on a website where they are authenticated, such as:
   - Changing account settings (e.g., email, password).
   - Transferring funds or making financial transactions.
   - Posting messages or comments.
   - Deleting or modifying content.

2. **Bypass of Access Control**: Since the attacker leverages the victim's authentication cookies, they bypass the need to authenticate themselves, making it difficult for the server to distinguish between a legitimate user and an attacker.

---

### **Defending Against CSRF**

1. **CSRF Tokens**:
   The most common and effective method of defending against CSRF is to use **anti-CSRF tokens**. These tokens are unique to each user session and are included in every form that requires a state-changing action. The server generates a token when the page is loaded and verifies it when the form is submitted.

   #### Example: Adding a CSRF Token to a Form

   ```html
   <form action="/transfer" method="POST">
       <input type="hidden" name="csrf_token" value="generated_token_from_server">
       <input type="text" name="recipient" value="victim123">
       <input type="number" name="amount" value="1000">
       <input type="submit" value="Transfer">
   </form>
   ```

   When the form is submitted, the server checks whether the submitted CSRF token matches the one stored in the user's session. If they don't match, the request is rejected.

   #### Server-side Code Example:

   ```python
   from flask import Flask, request, session, render_template_string, abort
   import secrets

   app = Flask(__name__)
   app.secret_key = "supersecretkey"

   def generate_csrf_token():
       token = secrets.token_hex(16)  # Generate a random token
       session['csrf_token'] = token  # Store it in the session
       return token

   @app.route('/transfer', methods=['GET', 'POST'])
   def transfer():
       if request.method == 'POST':
           csrf_token = request.form.get('csrf_token')
           if csrf_token != session.get('csrf_token'):
               abort(403)  # Forbidden if CSRF token doesn't match
           # Process transfer...
           return "Transfer Successful"
       return render_template_string('''
           <form action="/transfer" method="POST">
               <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
               <input type="text" name="recipient" value="victim123">
               <input type="number" name="amount" value="1000">
               <input type="submit" value="Transfer">
           </form>
       ''', csrf_token=generate_csrf_token())

   if __name__ == '__main__':
       app.run(debug=True)
   ```

   **Explanation**:
   - A CSRF token is generated by the server when the page is rendered and stored in the session.
   - The token is included in the form as a hidden field.
   - On form submission, the server compares the token in the request with the one stored in the session. If they don't match, the request is rejected with a `403 Forbidden` response.

2. **SameSite Cookies**:
   Setting the `SameSite` attribute on cookies can help prevent CSRF by ensuring that cookies are only sent with requests originating from the same site.

   ```python
   # Set SameSite attribute for cookies (works for cookies in most browsers)
   response.set_cookie('session_id', '123456', samesite='Strict')
   ```

   - **`SameSite=Strict`**: The cookie is sent only if the request is coming from the same origin.
   - **`SameSite=Lax`**: The cookie is sent for top-level navigation (like following a link), but not for sub-requests (e.g., iframes).
   - **`SameSite=None`**: The cookie is sent in all contexts, including cross-origin requests. Must be used in conjunction with `Secure`.

3. **Referer and Origin Header Checks**:
   The server can check the `Referer` or `Origin` HTTP headers of incoming requests to ensure that they are coming from a trusted source. This is less reliable than CSRF tokens, but it can be a useful additional layer of protection.

   ```python
   # Check the Referer or Origin headers
   referer = request.headers.get('Referer')
   origin = request.headers.get('Origin')
   if not referer.startswith('https://trusted-website.com') and not origin == 'https://trusted-website.com':
       abort(403)  # Forbidden if request is from an untrusted origin
   ```

4. **Avoid State-Change Requests with GET**:
   Never use GET requests for actions that modify data or perform state-changing operations (e.g., transferring money, changing passwords). GET requests should be safe and idempotent. Instead, use POST, PUT, or DELETE for these actions.

5. **Use Multi-Factor Authentication (MFA)**:
   If applicable, enforce multi-factor authentication for critical operations (e.g., transferring money), which can mitigate the impact of CSRF attacks.

---

### **Conclusion**

CSRF attacks exploit the trust a web application has in the user’s browser. By tricking the victim into submitting unauthorized requests, an attacker can perform actions as if they were the victim. To protect against CSRF:
- Use **CSRF tokens** for each state-changing request.
- Implement **SameSite cookies** to restrict cross-origin requests.
- Verify **Referer** or **Origin** headers to ensure requests come from trusted sources.
- Ensure that state-changing actions are never handled via GET requests.

By combining these techniques, you can significantly reduce the risk of CSRF attacks on your web applications.
