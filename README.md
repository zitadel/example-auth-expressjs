# Express.js with ZITADEL

[Express.js](https://expressjs.com/) is a popular and powerful framework for building the backend of web applications. In a traditional setup, often called a "Backend for Frontend" (BFF), your Express server manages both your application's logic and renders the web pages that users see.

To secure such an application, you need a reliable way to handle user logins. For the Express ecosystem, [Passport.js](http://www.passportjs.org/) is the standard and recommended middleware for authentication. Think of it as a flexible security guard for your app. This guide demonstrates how to use Passport.js with an Express v5 application to implement a secure login with ZITADEL.

We'll be using the **OpenID Connect (OIDC)** protocol with the **Authorization Code Flow + PKCE**. This is the industry-best practice for security, ensuring that the login process is safe from start to finish. You can learn more in our [guide to OAuth 2.0 recommended flows](https://zitadel.com/docs/guides/integrate/login/oidc/oauth-recommended-flows).

Explore our complete example application to see this in action.

## Resources

- **Example App Repository:** [Link to your future GitHub repository]
- **Express.js Documentation:** <https://expressjs.com/>
- **Passport.js Documentation:** <http://www.passportjs.org/>
- **Express Session Middleware:** <https://expressjs.com/en/resources/middleware/session.html>

## SDK

This example uses **Passport.js**, the standard for Express.js authentication. While ZITADEL doesn't offer a specific SDK, Passport.js is highly modular. It works with a "strategy" that handles the communication with ZITADEL. Under the hood, this example uses the powerful [`openid-client`](https://github.com/panva/node-openid-client) library to manage the secure OIDC PKCE flow.

Check out our Example Application to see it in action.

## Example Application

The example repository includes a complete Express.js application, ready to run, that demonstrates how to integrate ZITADEL for user authentication.

### Prerequisites

Before you begin, ensure you have the following installed on your system:

- Node.js (v20 or later is recommended)
- npm (usually comes with Node.js) or yarn

### Configuration

To run the application, you first need to copy the `.env.example` file to a new file named `.env` and fill in your ZITADEL application credentials.

```
# The network port where your Express application will listen for requests.
PORT=3000

# Defines the maximum age of a session in seconds. After this time, the user will need to log in again.
SESSION_DURATION=3600

# A long, random, and secret string used to sign the session ID cookie. This prevents tampering.
# Replace this with your own strong secret key.
SESSION_SECRET="your-very-secret-and-strong-session-key"

# The domain of your ZITADEL instance. You can find this in your ZITADEL console.
# Example: [https://your-instance-abcdef.zitadel.cloud/](https://your-instance-abcdef.zitadel.cloud/)
ZITADEL_DOMAIN="https://your-zitadel-domain"

# The unique Client ID for your application, obtained from the ZITADEL console.
ZITADEL_CLIENT_ID="your-client-id"

# (Optional) The Client Secret if you are using a confidential client type.
ZITADEL_CLIENT_SECRET=""

# The full URL that ZITADEL will redirect to after a successful login.
# This MUST match one of the Redirect URIs in your ZITADEL application settings.
ZITADEL_CALLBACK_URL="http://localhost:3000/auth/callback"
```

### Installation and Running

Follow these steps to get the application running:

```bash
# 1. Clone the repository
git clone [https://github.com/HackYourFuture/curriculum](https://github.com/HackYourFuture/curriculum)
cd [repository-name]

# 2. Install the project dependencies
npm install

# 3. Start the development server
npm start
```

The application will now be running at `http://localhost:3000`.

### What does the Example include?

- A public home page with a "Login" button.
- A secure user authentication flow using OIDC with PKCE.
- A middleware to protect specific routes.
- A private `/profile` page that is only accessible after a user logs in and displays their information.
- A `/logout` endpoint to clear the user's session.
