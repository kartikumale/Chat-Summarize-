Of course. Based on the configuration, requirements, and database schema you provided, here is a comprehensive `README.md` file for your SecureChat Pro project.

-----

# SecureChat Pro

SecureChat Pro is a feature-rich, secure messaging application built with Flask and Python. It provides a robust platform for private and group conversations, managed through a comprehensive admin dashboard. A key feature is the integration of the Groq API for powerful AI-driven chat summarization.

## Key Features

  - **Secure User Authentication**: Separate login and registration for regular users and administrators.
  - **Private & Group Chats**: Engage in one-to-one private messaging or create/join group conversations.
  - **Role-Based Access Control**: Admins can assign `read-write` or `read-only` permissions to users within groups.
  - **AI-Powered Summarization**: Leverage the Groq API to generate concise summaries of long chat histories, saving time and effort.
  - **Admin Dashboard**: A central hub for administrators to:
      - View user and group statistics.
      - Manage users (view activity, block/unblock).
      - Manage groups (create, delete, add/remove members, set roles).
      - Monitor all conversations.
  - **Media Sharing**: Users can share images, videos, and documents within chats.
  - **SQLite Database**: A lightweight, file-based database with a comprehensive schema, including views and triggers for data integrity and performance.

## Technology Stack

  - **Backend**: Flask
  - **Database**: SQLite
  - **AI Summarization**: Groq API
  - **Frontend**: HTML, Tailwind CSS, JavaScript
  - **Dependencies**: See `requirements.txt` section below.

-----

## Installation and Setup

Follow these steps to get the project running on your local machine.

### 1\. Prerequisites

  - Python 3.9 or higher
  - `pip` (Python package installer)
  - `git` for cloning the repository

### 2\. Clone the Repository

```bash
git clone <your-repository-url>
cd securechat-pro
```

### 3\. Set Up a Virtual Environment

It is highly recommended to use a virtual environment to manage project dependencies.

  - **On macOS/Linux:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
  - **On Windows:**
    ```bash
    python -m venv venv
    venv\Scripts\activate
    ```

### 4\. Create and Populate Project Files

You need to create two critical files: `requirements.txt` for the Python packages and `.env` for the environment variables.



#### C. `schema.sql` File

Create a file named `schema.sql` in the project's root directory and paste the entire database schema you provided.

### 5\. Install Dependencies

Install all the required Python packages from your `requirements.txt` file.

```bash
pip install -r requirements.txt
```

### 6\. Initialize the Database

The `schema.sql` file contains all the necessary commands to create the tables, indexes, views, and sample data. Run the following command from your project's root directory to initialize the SQLite database.

This command assumes your Flask application will create the database file at `instance/database.db`. If the path is different, adjust accordingly.

```bash
# Create the 'instance' directory if it doesn't exist
mkdir -p instance

# Initialize the database using the schema file
sqlite3 instance/database.db < schema.sql
```

You should now have a `database.db` file inside an `instance` folder.

-----

## Running the Application

Once the setup is complete, you can run the Flask application.

```bash
python app.py
```

You should see output similar to this, indicating the server is running:

```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000 (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: ...
```

## How to Access

  - **User Application**: Open your web browser and navigate to `http://127.0.0.1:5000`
  - **Admin Login**: Navigate to `http://127.0.0.1:5000/admin`

### **Admin Credentials**

A default administrator account is created by the `schema.sql` script.

  - **Username**: `admin`
  - **Password**: `admin123`

> **🚨 CRITICAL SECURITY NOTICE:** You must change the default admin password immediately after your first login, especially if you plan to deploy this application anywhere other than your local machine.

-----
