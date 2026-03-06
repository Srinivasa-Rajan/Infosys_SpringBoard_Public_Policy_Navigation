PolicyNav: Multilingual RAG, Knowledge Graphs & Intelligent Policy Navigation
Overview
PolicyNav is a Retrieval-Augmented Generation (RAG) system designed to help users navigate complex public policy documents. The platform integrates advanced Natural Language Processing (NLP) to bridge the gap between government terminology and citizen understanding through multilingual Q&A, automated summarization, and interactive relationship mapping.

AI Models and Their Purposes
The system leverages a specialized stack of machine learning models to process, retrieve, and translate information:

Qwen/Qwen2.5-1.5B-Instruct (LLM): This model acts as the core reasoning engine. It is used to generate highly concise English answers based on the retrieved context and to summarize lengthy policy documents into brief, 3-point summaries. It runs locally using 4-bit quantization via BitsAndBytes for efficient inference.

facebook/nllb-200-distilled-600M (Translation): This model handles cross-lingual intelligence. It translates user queries from native Indian languages into English for database searching, and then translates the LLM's English response back into the user's native language.

paraphrase-multilingual-MiniLM-L12-v2 (SentenceTransformer): This model generates high-quality text embeddings. It is used to convert chunks of policy documents into vector representations so they can be indexed and searched semantically within the FAISS vector database.

en_core_web_sm (spaCy): This model provides Named Entity Recognition (NER) capabilities. It automatically identifies specific entities such as Organizations, Laws, Locations, and People within the texts to build the interactive Knowledge Graph.

Key Features
1. Q&A Multi-Language Engine (RAG)
Semantic Search: Uses sentence-transformers to find relevant policy snippets from a FAISS vector store.

Cross-Lingual Intelligence: Supports querying and answering in Hindi, Tamil, Kannada, Telugu, Marathi, Bengali, and English.

Policy Simplification: Includes a toggle that instructs the LLM to explain complex laws at a middle-school reading level.

2. Multi-Language Summarization
Instant Briefs: Generates concise summaries of uploaded or pasted policy documents.

Direct Translation: Outputs summaries directly into any of the supported Indian languages.

3. Knowledge Graph Integration
Entity Extraction: Automatically identifies and categorizes key entities using spaCy.

Relationship Mapping: Maps how different entities connect across various policy documents.

Interactive Visualization: Renders a physics-based, zoomable bubble chart built with Pyvis for exploring policy ecosystems.

4. Integrated Security & User Interface
Authentication: Integrated email-based OTP verification for secure logins and password resets.

Advanced Dashboard: Features KPI cards, interactive Plotly gauges for readability metrics, and activity history tracking.

Role-Based Access: Maintains separate dashboard views and privileges for Administrators and standard users.

Installation and Setup
1. Install Required Dependencies
Run the following commands in your terminal to install the necessary Python packages and download the required spaCy model:

Bash
pip install streamlit pyjwt bcrypt python-dotenv pyngrok nltk streamlit-option-menu plotly textstat PyPDF2 pandas sentence-transformers faiss-cpu beautifulsoup4 spacy pyvis networkx transformers accelerate bitsandbytes
python -m spacy download en_core_web_sm
2. Configure Environment Variables
Set the following environment variables in your system or .env file before running the application:

EMAIL_ID: The email address used for sending OTPs.

EMAIL_APP_PASSWORD: The secure App Password for the sender email account.

JWT_SECRET_KEY: A secure random string used for session token encryption.

ADMIN_EMAIL_ID: The designated master administrator email address.

ADMIN_PASSWORD: The designated master administrator password.

NGROK_AUTHTOKEN: Your ngrok authentication token for remote tunneling.

3. Data Ingestion
Execute the cells in Policy_Ingestion_Cloud_DB.ipynb to scrape government policy landing pages and download the PDFs to your local storage or Google Drive. This will also set up the policies_meta.db SQLite database.

Run the ingestion scripts within the main application to process the text and build the FAISS index.

Running the Application
Launch the Streamlit dashboard by running:

Bash
streamlit run app.py
