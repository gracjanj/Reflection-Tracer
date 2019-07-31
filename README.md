# Follower
Follower is a Burp extension that let's you generate unique values for tested parameters and follow their reflections on your target application. This is particularly useful in finding XSS, SSTI and other vulnerabilities. It also adds unique value to each parameter tested during Active Scanning.

# Installation
- Download the Follower.jar file.
- In Burp Suite open Extender tab. In Extensions tab, click Add button.
- Choose downloaded jar file -> Next.
- Check installation for no error messages.

# Example usage
1. Set scope in target tab
2. Right click -> 'Generate Follower'. Unique value is now in your clipboard.
3. Paste string as a parameter value.
4. Crawl website manually/automatically.
5. Results will be available in Follower tab
    - Request1 is the request that introduced value to the application
    - Request2 is the request that triggered the response containing value from step 1
    - Response is the response that contains reflected value

# Changelog
**1.0 Release**
