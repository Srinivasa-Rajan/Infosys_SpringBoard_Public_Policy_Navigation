# PolicyNav: Milestone 3 - AI Intelligence & Multilingual Engine

This milestone marks the integration of advanced Natural Language Processing (NLP) and Retrieval-Augmented Generation (RAG) to transform static policy documents into an interactive, multilingual knowledge base.

## 1. Q&A Multi-Language Engine
The core of the "Public Policy Compass" is a bi-directional RAG system that allows users to query complex documents in their native tongue.

* **Core LLM**: Utilizes **Qwen 2.5-1.5B-Instruct** for generating precise, context-aware answers based on retrieved document snippets.
* **Multilingual Support**: Integrated with **Facebook's NLLB-200 (600M distilled)** to support high-fidelity translation for English, Hindi, Tamil, Kannada, Telugu, Marathi, and Bengali.
* **Semantic Retrieval**: Uses **FAISS (Facebook AI Similarity Search)** combined with the `paraphrase-multilingual-MiniLM-L12-v2` embedder to find relevant policy sections across language barriers.
* **Language Simplification**: Includes a "Simplify Language" toggle that adjusts the LLM prompt to rephrase complex legal jargon into middle-school level English.

![AI Chat Function Interface](AI_CHAT.png)

## 2. Multi-Language Summarization
This module allows users to upload lengthy policy PDFs and receive immediate, actionable insights in their preferred language.

* **Dynamic Extraction**: Automatically extracts text from uploaded `.pdf` or `.txt` files using **PyPDF2**.
* **Concise Output**: The engine is prompted to condense documents into three highly concise bullet points to ensure readability for general citizens.
* **Cross-Language Output**: Summaries can be generated directly into any supported Indian language, regardless of the source document's original language.

![Document Summarization Module](AI_SUMMARY.png)

## 3. Policy Knowledge Graph
To visualize the complex web of government acts and organizations, a Knowledge Graph is extracted from the vector store.

* **Entity Extraction**: Uses **spaCy (en_core_web_sm)** Named Entity Recognition (NER) to identify Organizations (ORG), Laws (LAW), Locations (GPE), and Products/Schemes.
* **Relationship Mapping**: Maps connections between entities based on their co-occurrence within the same policy document chunks.
* **Interactive Visualization**: Built with **PyVis** and **NetworkX**, featuring hover effects to highlight paths and a double-click "Focus Mode" to filter specific clusters.

![Policy Knowledge Graph Visualization](KNOWLEDGE_GRAPH.png)

## Installation & Execution (Milestone 3)

### Dependency Setup
```bash
pip install streamlit pyjwt bcrypt python-dotenv pyngrok nltk streamlit-option-menu plotly textstat PyPDF2 pandas \
    sentence-transformers faiss-cpu beautifulsoup4 spacy pyvis networkx \
    transformers accelerate bitsandbytes -q
python -m spacy download en_core_web_sm -q
