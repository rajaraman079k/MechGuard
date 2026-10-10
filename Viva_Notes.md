# MechGuard AI — UI Edition Viva Notes

**What did you add?**  
A landing page, local account registration/sign-in, dark/light theme switch, and separate navigation pages.

**How are passwords stored?**  
A random salt and PBKDF2-HMAC-SHA256 password hash are stored in SQLite. The plain password is not saved.

**Is this production-grade authentication?**  
No. It is suitable for a local classroom demo. A deployed multi-user system would need stronger session management, rate limiting, secure deployment, account recovery, and other security controls.

**How does dark/light mode work?**  
The user chooses a theme in the sidebar. Streamlit reruns and custom CSS updates the background, panels, cards, and text colors.

**How is user data separated?**  
Each assessment stores the username of the account that created it. History queries filter by the signed-in username.

**Does it use an API?**  
No external AI API is used. The application and diagnostic logic run locally.

**What is the main limitation?**  
It is a rule-based decision-support prototype. Thresholds are illustrative and the app is not validated for real machinery.
