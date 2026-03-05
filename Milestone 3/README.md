Milestone 3 - Multilingual RAG, Knowledge Graphs \& Intelligent Policy Navigation

🚀 Overview

Milestone 3 transforms the platform into PolicyNav, a sophisticated Retrieval-Augmented Generation (RAG) system. This version integrates advanced Natural Language Processing (NLP) to help users navigate complex public policy documents through multilingual Q\&A, automated summarization, and interactive relationship mapping (Knowledge Graphs), all while maintaining the secure authentication and readability standards established in previous milestones.



🛠️ Description

PolicyNav leverages high-performance LLMs (Qwen 2.5) and translation models (NLLB-200) to bridge the gap between complex government jargon and citizen understanding. The system ingests PDF/HTML policy documents into a FAISS vector database, allows users to query them in multiple Indian languages, and visualizes the underlying connections between government entities using spaCy NER and Pyvis.



✨ Key Features (Milestone 3)

1\. Q\&A Multi-Language Engine (RAG)

Semantic Search: Uses sentence-transformers to find relevant policy snippets from a FAISS vector store.



Cross-Lingual Intelligence: Ask questions in native languages (Hindi, Tamil, etc.). The system translates the query, searches English docs, and translates the answer back.



Policy Simplification: A "Simplify" toggle that instructs the LLM to explain complex laws at a middle-school reading level.



2\. Multi-Language Summarization

Instant Briefs: Generates 3-point concise summaries of long policy documents.



Direct Translation: Summaries can be output directly in any of the 7 supported Indian languages.



3\. Knowledge Graph Integration

Entity Extraction: Automatically identifies Organizations (ORG), Laws (LAW), Locations (GPE), and People using spaCy.



Relationship Mapping: Maps how different entities are connected across various policy documents.



Interactive Visualization: A physics-based, zoomable bubble chart built with Pyvis for exploring policy ecosystems.



4\. Integrated Security \& UI/UX

OTP Authentication: Fully integrated email-based 2FA for logins and password resets.



Advanced Dashboard: A modern, dark-themed UI featuring KPI cards, interactive Plotly gauges for readability, and activity history tracking.



Role-Based Access: Separate views for Admins (User management/Security monitoring) and standard users.



📥 Installation \& Setup

1\. Install Required Dependencies

`Bash`

`pip install streamlit pyjwt bcrypt python-dotenv pyngrok nltk streamlit-option-menu \\`

`&nbsp;   plotly textstat PyPDF2 pandas sentence-transformers faiss-cpu \\`

`&nbsp;   beautifulsoup4 spacy pyvis networkx transformers accelerate bitsandbytes`

`python -m spacy download en\_core\_web\_sm`

2\. Configure Environment Variables

You must set the following keys in your environment (or Colab userdata):



GMAIL\_ID: The email for sending OTPs.



GMAIL\_APP\_PASS: Secure App Password for the Gmail account.



JWT\_SECRET\_KEY: Random string for session security.



ADMIN\_EMAIL\_ID: Designated master admin email.



NGROK\_AUTHTOKEN: Your token from ngrok.com (for remote access).



3\. Data Ingestion

Run the Policy\_Ingestion\_Cloud\_DB.ipynb to scrape government PDFs into your Google Drive.



Run the Ingest cell in the main application to build the FAISS index.



🚀 Running the Application

`Bash`

`streamlit run app.py `

📊 Technical Stack

Frontend: Streamlit (Custom Dark Theme)



Database: SQLite3 (User Metadata) \& FAISS (Vector Store)



LLM Engine: Qwen/Qwen2.5-1.5B-Instruct (4-bit Quantization)



Translation: facebook/nllb-200-distilled-600M



Graphs: NetworkX \& Pyvis



Metrics: Textstat (Readability)



