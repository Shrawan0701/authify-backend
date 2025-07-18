# Authify: Full-Stack Authentication System

##  Architecture

Authify is built on a **Client-Server Architecture**, specifically as a **Single-Page Application (SPA) with a RESTful API Backend**.

* The **Frontend (React.js)** acts as a decoupled client, handling all UI rendering and client-side routing.
* The **Backend (Spring Boot)** exposes a comprehensive set of RESTful APIs, handling business logic, data and all security aspects (authentication, authorization).
* Communication between the frontend and backend occurs exclusively via **HTTP requests** (JSON payload) to the REST API endpoints.
* The two components are deployed independently, showcasing a modern, modular approach to full-stack development.

##  Live Demo

Experience Authify in action:

* **Frontend Application:** [https://authify-frontend.vercel.app](https://authify-frontend.vercel.app)
* **Backend API Base URL:** [https://authify-backend-lei1.onrender.com/api/v1.0](https://authify-backend-lei1.onrender.com/api/v1.0)
    *(This is the base URL for API endpoints. You will see an "Unauthorized" message when visiting directly, which is expected for a secured API.)*

##  Features

* **User Registration (Sign Up):** Securely create new user accounts.
* **User Login:** Authenticate users with JWT (JSON Web Tokens) for secure session management.
* **Authentication Persistence:** Maintain user login status across page refreshes using HttpOnly.
* **Email Verification (OTP):** OTP-based email verification for new registrations and resend options.
* **Password Reset (OTP):** Securely reset forgotten passwords via OTP sent to registered email.
* **User Logout:** Securely terminate user sessions.
* **Responsive UI:** Adapts seamlessly across various devices using Bootstrap.
* **Error Handling:** Clear and informative messages for both API and UI errors.

## 💻 Tech Stack

### Frontend

* **React.js:** JavaScript library for building user interfaces.
* **Vite:** Fast frontend build tool.
* **JavaScript (ES6+):** Programming language.
* **Bootstrap:** Responsive CSS framework.
* **React Router DOM:** For client-side routing.
* **Axios:** Promise-based HTTP client for API requests.
* **React Toastify:** For elegant notification messages.

### Backend

* **Java:** Programming language.
* **Spring Boot:** Framework for building robust, stand-alone, production-grade Spring applications.
* **Spring Security:** Comprehensive security for authentication and authorization.
* **Spring Data JPA & Hibernate:** For ORM (Object-Relational Mapping) and database interaction.
* **Maven:** Dependency management and build automation tool.
* **Lombok:** Reduces boilerplate code.
* **jjwt:** Java JWT library for token generation and validation.
* **Jakarta Mail (via Brevo):** For sending transactional emails.

### Database

* **MySQL:** Relational database management system.
* **Railway.app:** Cloud-hosted managed MySQL service (used for production database).

### Deployment

* **Vercel:** Platform for deploying frontend applications (used for React app).
* **Render:** Cloud platform for deploying web services (used for Spring Boot backend).

### Contact
Feel free to connect or reach out if you have questions about this project!

Email: shrawanrw07@gmail.com

LinkedIn Profile: https://www.linkedin.com/in/shrawanwandhekar/
