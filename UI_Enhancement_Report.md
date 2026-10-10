# MechGuard AI — User Interface Enhancement

## Added features
- Landing page introducing the application and its functions.
- Local account creation and sign-in.
- Salted password hashing using PBKDF2-HMAC-SHA256.
- Dark and light appearance selection.
- Navigation for Home, Agent workspace, Machine memory, CSV & trends, and System guide.
- Assessment history filtered by the signed-in username.

## Implementation
The interface uses Streamlit and CSS styling. SQLite stores users and assessments. Passwords are never saved in plaintext; each password is hashed with a random salt. Existing assessment databases are upgraded by adding a username column when needed.

## Limitations
This authentication is intended for a local educational demonstration, not a public multi-user production service. Thresholds remain illustrative, and the agent uses deterministic rules rather than an LLM or trained prediction model.
