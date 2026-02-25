import os
import re
import requests
import hashlib
import zipfile
import shutil
import json
import base64
import ast
import subprocess
import logging
import sys
import time
from typing import Dict, Any
from io import BytesIO, StringIO
from urllib.parse import urljoin, urlparse, unquote

# Third-party imports
from bs4 import BeautifulSoup
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# Groq AI Setup
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("⚠️ Groq not installed. Run: pip install groq")

# Black formatting (Optional, wrapped in try-except)
try:
    import black
    BLACK_AVAILABLE = True
except ImportError:
    BLACK_AVAILABLE = False

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot token & API Keys - It's better to use Environment Variables
BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "YOUR_GROQ_API_KEY_HERE")
PORT = int(os.environ.get('PORT', '8443'))  # Port for Render

# Store user states and data
user_states = {}
user_data = {}

class GroqAI:
    """Groq AI Integration for smart responses"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = None
        if GROQ_AVAILABLE and api_key and api_key != "YOUR_GROQ_API_KEY_HERE":
            try:
                self.client = Groq(api_key=api_key)
                print("✅ Groq AI initialized successfully!")
            except Exception as e:
                print(f"❌ Groq initialization error: {e}")
    
    def ask(self, prompt, system_prompt="You are a helpful coding assistant."):
        """Ask Groq AI anything"""
        if not self.client:
            return "❌ Groq AI not configured. Please add your API key."
        
        try:
            completion = self.client.chat.completions.create(
                model="mixtral-8x7b-32768",  # or "llama2-70b-4096"
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            return completion.choices[0].message.content
        except Exception as e:
            return f"❌ Groq AI Error: {str(e)}"
    
    def generate_code(self, description, filename=None):
        """Generate code based on description"""
        prompt = f"""Generate complete working code for: {description}
        
        Requirements:
        - Write clean, well-documented code
        - Include error handling
        - Make it production-ready
        - Add comments in Bengali if possible
        
        Return only the code without explanations."""
        
        if filename:
            ext = filename.split('.')[-1].lower()
            if ext == 'py':
                prompt += "\nLanguage: Python"
            elif ext == 'html':
                prompt += "\nLanguage: HTML with CSS"
            elif ext == 'js':
                prompt += "\nLanguage: JavaScript"
            elif ext == 'php':
                prompt += "\nLanguage: PHP"
        
        return self.ask(prompt)
    
    def extract_info_from_code(self, code):
        """Extract important information from code"""
        prompt = f"""Analyze this code and extract:
        1. All passwords, API keys, tokens
        2. Login credentials
        3. Database connections
        4. Secret keys
        5. Email passwords
        6. Any sensitive information
        
        Code:
        {code[:3000]}  # Limit to 3000 chars
        
        Return as JSON with categories."""
        
        response = self.ask(prompt, "You are a security expert. Extract sensitive data.")
        return response

class AdvancedFileHacker:
    """Advanced file hacking and code extraction"""
    
    @staticmethod
    def hack_file(file_path):
        """Extract all code and sensitive information from any file"""
        results = {
            'file_info': {},
            'code_content': '',
            'sensitive_data': [],
            'passwords': [],
            'api_keys': [],
            'tokens': [],
            'database_connections': [],
            'emails': [],
            'urls': [],
            'functions': [],
            'classes': [],
            'imports': []
        }
        
        try:
            # Get file info
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            results['file_info'] = {
                'name': os.path.basename(file_path),
                'extension': file_ext,
                'size': file_size,
                'size_kb': round(file_size / 1024, 2)
            }
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            results['code_content'] = content[:5000]  # First 5000 chars
            
            # Extract sensitive data based on file type
            if file_ext == '.py':
                AdvancedFileHacker._hack_python(content, results)
            elif file_ext in ['.html', '.htm']:
                AdvancedFileHacker._hack_html(content, results)
            elif file_ext == '.js':
                AdvancedFileHacker._hack_javascript(content, results)
            elif file_ext == '.php':
                AdvancedFileHacker._hack_php(content, results)
            elif file_ext == '.json':
                AdvancedFileHacker._hack_json(content, results)
            else:
                AdvancedFileHacker._hack_generic(content, results)
            
            # Common patterns for all files
            AdvancedFileHacker._extract_common_patterns(content, results)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    @staticmethod
    def _hack_python(content, results):
        """Extract from Python files"""
        # Extract imports
        import_pattern = r'^(?:from|import)\s+(\w+)'
        results['imports'] = re.findall(import_pattern, content, re.MULTILINE)
        
        # Extract functions
        func_pattern = r'def\s+(\w+)\s*\(([^)]*)\)'
        results['functions'] = re.findall(func_pattern, content)
        
        # Extract classes
        class_pattern = r'class\s+(\w+)\s*[\(:]'
        results['classes'] = re.findall(class_pattern, content)
        
        # Extract Django/Flask secrets
        secret_patterns = [
            (r'SECRET_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', 'Django Secret'),
            (r'sqlalchemy\.database_uri.*?[\'"]([^\'"]+)[\'"]', 'DB URI'),
            (r'mongodb://[^\s"\']+', 'MongoDB URI'),
            (r'mysql://[^\s"\']+', 'MySQL URI'),
            (r'postgresql://[^\s"\']+', 'PostgreSQL URI'),
        ]
        
        for pattern, desc in secret_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                results['sensitive_data'].append(f"{desc}: {match}")
        
        # AST parsing for advanced extraction
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and 'password' in target.id.lower():
                            # Python 3.7+ compatibility for string value
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                results['passwords'].append(f"Variable '{target.id}': {node.value.value}")
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if 'login' in node.func.attr.lower() or 'authenticate' in node.func.attr.lower():
                            for arg in node.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    results['sensitive_data'].append(f"Login param: {arg.value}")
        except:
            pass
    
    @staticmethod
    def _hack_html(content, results):
        """Extract from HTML files"""
        soup = BeautifulSoup(content, 'html.parser')
        
        # Extract forms
        forms = soup.find_all('form')
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', ''),
                'inputs': []
            }
            for inp in form.find_all('input'):
                if inp.get('type') == 'password':
                    results['passwords'].append(f"Password field: {inp.get('name', 'unnamed')}")
            results['sensitive_data'].append(f"Form: {json.dumps(form_data)}")
        
        # Extract scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for passwords in JS
                pwd_matches = re.findall(r'password\s*[:=]\s*["\']([^"\']+)["\']', script.string, re.I)
                for match in pwd_matches:
                    results['passwords'].append(f"JS Password: {match}")
        
        # Extract meta tags
        metas = soup.find_all('meta')
        for meta in metas:
            if meta.get('name') in ['csrf-token', 'api-key']:
                results['tokens'].append(f"{meta.get('name')}: {meta.get('content')}")
    
    @staticmethod
    def _hack_javascript(content, results):
        """Extract from JavaScript files"""
        patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
            (r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Token'),
            (r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Password'),
            (r'auth["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Auth'),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Secret'),
            (r'firebase\.initializeApp\({([^}]+)}', 'Firebase Config'),
        ]
        
        for pattern, desc in patterns:
            matches = re.findall(pattern, content, re.I | re.S)
            for match in matches:
                results['sensitive_data'].append(f"{desc}: {match}")
    
    @staticmethod
    def _hack_php(content, results):
        """Extract from PHP files"""
        patterns = [
            (r'\$password\s*=\s*["\']([^"\']+)["\']', 'PHP Password'),
            (r'\$db_password\s*=\s*["\']([^"\']+)["\']', 'DB Password'),
            (r'mysql_connect\([^,]+,\s*["\']([^"\']+)["\']', 'MySQL User'),
            (r'mysql_connect\([^,]+,\s*[^,]+,\s*["\']([^"\']+)["\']', 'MySQL Password'),
            (r'define\(["\']DB_PASSWORD["\'],\s*["\']([^"\']+)["\']\)', 'DB Password Constant'),
        ]
        
        for pattern, desc in patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                results['sensitive_data'].append(f"{desc}: {match}")
    
    @staticmethod
    def _hack_json(content, results):
        """Extract from JSON files"""
        try:
            data = json.loads(content)
            
            def extract_sensitive(obj, path=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_path = f"{path}.{key}" if path else key
                        if any(term in key.lower() for term in ['password', 'pass', 'pwd', 'secret', 'token', 'api', 'key']):
                            results['sensitive_data'].append(f"{new_path}: {value}")
                        elif isinstance(value, (dict, list)):
                            extract_sensitive(value, new_path)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        extract_sensitive(item, f"{path}[{i}]")
            
            extract_sensitive(data)
        except:
            pass
    
    @staticmethod
    def _hack_generic(content, results):
        """Generic extraction for any file"""
        pass
    
    @staticmethod
    def _extract_common_patterns(content, results):
        """Extract common patterns from any file"""
        # Email addresses
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', content)
        results['emails'] = list(set(emails))[:20]
        
        # URLs
        urls = re.findall(r'https?://[^\s"\']+', content)
        results['urls'] = list(set(urls))[:20]
        
        # API Keys (common patterns)
        api_patterns = [
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'sk-[0-9a-zA-Z]{48}', 'OpenAI API Key'),
            (r'[0-9a-f]{32}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID'),
            (r'gh[pousr]_[0-9a-zA-Z]{36}', 'GitHub Token'),
            (r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}', 'Slack Token'),
        ]
        
        for pattern, desc in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                results['api_keys'].append(f"{desc}: {match}")
        
        # Passwords from text
        pwd_patterns = [
            (r'password[=:]\s*(\S+)', 'Password'),
            (r'pass[=:]\s*(\S+)', 'Pass'),
            (r'pwd[=:]\s*(\S+)', 'Pwd'),
        ]
        
        for pattern, desc in pwd_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                if len(match) > 3 and not match.startswith(('http', 'www')):
                    results['passwords'].append(f"{desc}: {match}")

class FileGenerator:
    """Generate files from code descriptions"""
    
    @staticmethod
    def generate_file(code, filename):
        """Generate a file with given code"""
        try:
            # Create directory if not exists
            os.makedirs('generated_files', exist_ok=True)
            
            # Clean filename
            filename = re.sub(r'[^\w\-_\.]', '', filename)
            filepath = os.path.join('generated_files', filename)
            
            # Format code if Python
            if filename.endswith('.py') and BLACK_AVAILABLE:
                try:
                    code = black.format_str(code, mode=black.Mode())
                except:
                    pass
            
            # Write file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(code)
            
            return filepath
        except Exception as e:
            return None
    
    @staticmethod
    def cleanup_file(filepath):
        """Remove generated file"""
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except:
            pass

class WebsiteCracker:
    @staticmethod
    def download_website(url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            domain = urlparse(url).netloc.replace('.', '_')
            timestamp = int(time.time())
            folder_name = f"{domain}_{timestamp}"
            os.makedirs(folder_name, exist_ok=True)
            
            html_path = os.path.join(folder_name, 'index.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(str(soup))
            
            zip_path = f"{folder_name}.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(html_path, 'index.html')
            
            return zip_path, len(response.text)
            
        except Exception as e:
            logger.error(f"Download error: {e}")
            return None, 0
    
    @staticmethod
    def cleanup_file(filepath):
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
            folder = filepath.replace('.zip', '')
            if os.path.exists(folder):
                shutil.rmtree(folder)
        except:
            pass

class AdvancedPasswordExtractor:
    @staticmethod
    def extract_all_passwords(html_content):
        results = {
            'hardcoded_passwords': [],
            'password_fields': [],
            'login_forms': [],
            'hashes': [],
            'encoded_passwords': [],
            'javascript_passwords': [],
            'api_endpoints': [],
            'tokens': [],
            'session_data': [],
            'suspicious_patterns': []
        }
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Password input fields
        password_inputs = soup.find_all('input', {'type': 'password'})
        for inp in password_inputs:
            field_info = {
                'name': inp.get('name', 'N/A'),
                'id': inp.get('id', 'N/A'),
                'class': inp.get('class', 'N/A'),
                'placeholder': inp.get('placeholder', 'N/A'),
                'autocomplete': inp.get('autocomplete', 'N/A'),
                'value': inp.get('value', 'N/A')
            }
            results['password_fields'].append(field_info)
        
        # Hardcoded passwords
        password_patterns = [
            (r'password[=:]\s*[\'"]([^\'"]+)[\'"]', 'Password attribute'),
            (r'pwd[=:]\s*[\'"]([^\'"]+)[\'"]', 'pwd attribute'),
            (r'pass[=:]\s*[\'"]([^\'"]+)[\'"]', 'pass attribute'),
            (r'(?:var|let|const)\s+password\s*=\s*[\'"]([^\'"]+)[\'"]', 'JS var password'),
            (r'(?:var|let|const)\s+pass\s*=\s*[\'"]([^\'"]+)[\'"]', 'JS var pass'),
        ]
        
        for pattern, desc in password_patterns:
            matches = re.findall(pattern, html_content, re.I)
            for match in matches[:20]:
                if match and len(match) > 2:
                    results['hardcoded_passwords'].append({
                        'value': match,
                        'type': desc
                    })
        
        # Hashes
        hash_patterns = [
            (r'[a-f0-9]{32}', 'MD5'),
            (r'[a-f0-9]{40}', 'SHA1'),
            (r'[a-f0-9]{64}', 'SHA256'),
        ]
        
        for pattern, desc in hash_patterns:
            matches = re.findall(pattern, html_content)
            for match in set(matches)[:20]:
                results['hashes'].append({
                    'hash': match,
                    'type': desc
                })
        
        return results
    
    @staticmethod
    def format_advanced_results(results):
        output = []
        output.append("🔍 *পাসওয়ার্ড এক্সট্রাকশন রেজাল্ট*\n")
        
        if results['hardcoded_passwords']:
            output.append("🔑 *হার্ডকোডেড পাসওয়ার্ড:*")
            for i, item in enumerate(results['hardcoded_passwords'][:20], 1):
                output.append(f"{i}. `{item['value']}`  *[ {item['type']} ]*")
        
        if results['password_fields']:
            output.append("\n📝 *পাসওয়ার্ড ইনপুট ফিল্ড:*")
            for i, field in enumerate(results['password_fields'][:10], 1):
                output.append(f"{i}. ID: `{field['id']}`, Name: `{field['name']}`")
                output.append(f"   Placeholder: `{field['placeholder']}`")
        
        if results['hashes']:
            output.append("\n🔐 *ক্রিপ্টোগ্রাফিক হ্যাশ:*")
            for i, item in enumerate(results['hashes'][:10], 1):
                output.append(f"{i. `{item['hash']}`  *[ {item['type']} ]*")
        
        if not any(results.values()):
            output.append("❌ কোনো পাসওয়ার্ড পাওয়া যায়নি।")
        
        return "\n".join(output)

# Initialize Groq
groq_ai = GroqAI(GROQ_API_KEY)

# Bot command handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with inline keyboard"""
    keyboard = [
        [InlineKeyboardButton("🤖 Groq AI Chat", callback_data='groq')],
        [InlineKeyboardButton("🔓 File Hacker", callback_data='hack')],
        [InlineKeyboardButton("🔑 Password Extractor", callback_data='extract')],
        [InlineKeyboardButton("📁 File Generator", callback_data='generate')],
        [InlineKeyboardButton("🌐 Website Downloader", callback_data='website')]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = """
🚀 *সুপার অ্যাডভান্সড সিকিউরিটি বট*

*নতুন ফিচারসমূহ:*

🤖 *Groq AI Chat*
   • যেকোনো প্রশ্নের উত্তর
   • কোড জেনারেশন
   • টেকনিক্যাল হেল্প

🔓 *File Hacker*
   • যেকোনো ফাইল হ্যাক করুন
   • সব কোড বের করুন
   • সেনসিটিভ ডাটা এক্সট্রাক্ট

🔑 *Password Extractor*
   • পাসওয়ার্ড খুঁজুন
   • API Keys বের করুন
   • টোকেন ডিটেক্ট করুন

📁 *File Generator*
   • কোড থেকে ফাইল বানান
   • বিভিন্ন ফরম্যাট সাপোর্ট

🌐 *Website Downloader*
   • HTML ডাউনলোড
   • সোর্স কোড সেভ

_শুধুমাত্র শিক্ষামূলক উদ্দেশ্যে!_
    """
    
    await update.message.reply_text(
        welcome_text,
        parse_mode='Markdown',
        reply_markup=reply_markup
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button clicks"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    
    if query.data == 'groq':
        user_states[user_id] = 'groq_chat'
        await query.edit_message_text(
            "🤖 *Groq AI Chat*\n\n"
            "আপনি কি জানতে চান? যেকোনো প্রশ্ন করুন:\n"
            "- কোডিং হেল্প\n"
            "- টেকনিক্যাল প্রবলেম\n"
            "- জেনারেল নলেজ\n\n"
            "উদাহরণ: 'একটি ক্যালকুলেটর বানানোর কোড দাও'",
            parse_mode='Markdown'
        )
    
    elif query.data == 'hack':
        user_states[user_id] = 'waiting_file_hack'
        await query.edit_message_text(
            "🔓 *File Hacker*\n\n"
            "যেকোনো ফাইল আপলোড করুন। আমি ফাইলের ভিতর থেকে সব কোড এবং সেনসিটিভ ডাটা বের করব:\n"
            "- পাসওয়ার্ড\n"
            "- API Keys\n"
            "- টোকেন\n"
            "- ডাটাবেস কানেকশন\n"
            "- ইমেইল\n"
            "- ফাংশন/ক্লাস\n\n"
            "সাপোর্টেড ফাইল: .py, .html, .js, .php, .json, .txt",
            parse_mode='Markdown'
        )
    
    elif query.data == 'extract':
        user_states[user_id] = 'waiting_extract'
        await query.edit_message_text(
            "🔑 *Password & Sensitive Data Extractor*\n\n"
            "HTML/JS/PHP ফাইল আপলোড করুন অথবা কোড পেস্ট করুন।\n"
            "আমি সব ধরনের সেনসিটিভ ডাটা বের করব:\n"
            "- হার্ডকোডেড পাসওয়ার্ড\n"
            "- API Keys\n"
            "- টোকেন\n"
            "- ডাটাবেস ক্রিডেনশিয়াল\n"
            "- এনক্রিপ্টেড ডাটা",
            parse_mode='Markdown'
        )
    
    elif query.data == 'generate':
        user_states[user_id] = 'waiting_generate'
        await query.edit_message_text(
            "📁 *File Generator*\n\n"
            "আপনি কি ধরনের ফাইল বানাতে চান?\n"
            "ফরম্যাট: [ফাইলের নাম] [কোডের বিবরণ]\n\n"
            "উদাহরণ: 'calculator.py একটি ক্যালকুলেটর বানাও যেখানে যোগ, বিয়োগ, গুণ, ভাগ হবে'\n"
            "উদাহরণ: 'login.html একটি লগইন পেজ বানাও লাল থিমে'",
            parse_mode='Markdown'
        )
    
    elif query.data == 'website':
        user_states[user_id] = 'waiting_website'
        await query.edit_message_text(
            "🌐 *Website Downloader*\n\n"
            "ওয়েবসাইটের URL দিন। আমি HTML ডাউনলোড করে জিপ ফাইল হিসেবে দিব।\n\n"
            "উদাহরণ: https://example.com",
            parse_mode='Markdown'
        )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages"""
    user_id = update.effective_user.id
    text = update.message.text
    
    # Groq AI Chat
    if user_states.get(user_id) == 'groq_chat':
        await update.message.reply_text("🤔 Groq AI ভাবছে...")
        
        response = groq_ai.ask(text)
        
        # Split long messages
        if len(response) > 4000:
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for i, part in enumerate(parts, 1):
                await update.message.reply_text(
                    f"*Groq AI (Part {i}/{len(parts)}):*\n\n{part}",
                    parse_mode='Markdown'
                )
        else:
            await update.message.reply_text(
                f"*Groq AI:*\n\n{response}",
                parse_mode='Markdown'
            )
    
    # Website Downloader
    elif user_states.get(user_id) == 'waiting_website':
        await update.message.reply_text("⏳ ওয়েবসাইট ডাউনলোড হচ্ছে...")
        
        cracker = WebsiteCracker()
        zip_path, size = cracker.download_website(text)
        
        if zip_path and os.path.exists(zip_path):
            with open(zip_path, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=os.path.basename(zip_path),
                    caption=f"✅ ওয়েবসাইট ডাউনলোড সম্পন্ন!\nসাইজ: {size} অক্ষর"
                )
            cracker.cleanup_file(zip_path)
        else:
            await update.message.reply_text("❌ ওয়েবসাইট ডাউনলোড ব্যর্থ।")
        
        user_states.pop(user_id, None)
    
    # File Generator
    elif user_states.get(user_id) == 'waiting_generate':
        await update.message.reply_text("📝 ফাইল জেনারেট করা হচ্ছে...")
        
        # Parse filename and description
        parts = text.split(' ', 1)
        if len(parts) < 2:
            await update.message.reply_text("❌ ফরম্যাট: [ফাইলের নাম] [বিবরণ]\nউদাহরণ: calculator.py একটি ক্যালকুলেটর বানাও")
            return
        
        filename = parts[0]
        description = parts[1]
        
        # Generate code using Groq
        code = groq_ai.generate_code(description, filename)
        
        if "❌" in code:
            await update.message.reply_text(code)
            return
        
        # Create file
        filepath = FileGenerator.generate_file(code, filename)
        
        if filepath:
            with open(filepath, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=filename,
                    caption=f"✅ ফাইল তৈরি সম্পন্ন!\nফাইলের নাম: {filename}\nসাইজ: {os.path.getsize(filepath)} bytes"
                )
            FileGenerator.cleanup_file(filepath)
        else:
            await update.message.reply_text("❌ ফাইল তৈরি ব্যর্থ।")
        
        user_states.pop(user_id, None)
    
    # Password Extractor from text
    elif user_states.get(user_id) == 'waiting_extract':
        await update.message.reply_text("🔍 ডাটা এক্সট্রাক্ট করা হচ্ছে...")
        
        # Use Groq for smart extraction
        groq_results = groq_ai.extract_info_from_code(text)
        
        # Use local extractor as backup
        extractor = AdvancedPasswordExtractor()
        local_results = extractor.extract_all_passwords(text)
        local_formatted = extractor.format_advanced_results(local_results)
        
        # Combine results
        response = f"{local_formatted}\n\n🤖 *Groq AI Analysis:*\n{groq_results}"
        
        if len(response) > 4000:
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for i, part in enumerate(parts, 1):
                await update.message.reply_text(
                    f"*ফলাফল (পার্ট {i}/{len(parts)}):*\n\n{part}",
                    parse_mode='Markdown'
                )
        else:
            await update.message.reply_text(response, parse_mode='Markdown')
        
        user_states.pop(user_id, None)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle document uploads"""
    user_id = update.effective_user.id
    state = user_states.get(user_id)
    
    if not state:
        await update.message.reply_text("❌ আগে একটা অপশন সিলেক্ট করুন। /start দিন")
        return
    
    file = await update.message.document.get_file()
    file_name = update.message.document.file_name
    
    # Download file
    file_bytes = await file.download_as_bytearray()
    
    # File Hacker
    if state == 'waiting_file_hack':
        await update.message.reply_text(f"🔓 ফাইল হ্যাক করা হচ্ছে: {file_name}")
        
        # Save temp file
        temp_path = f"temp_{int(time.time())}_{file_name}"
        with open(temp_path, 'wb') as f:
            f.write(file_bytes)
        
        # Hack the file
        results = AdvancedFileHacker.hack_file(temp_path)
        
        # Format results
        response = []
        response.append(f"📁 *ফাইল ইনফো:*")
        response.append(f"নাম: {results['file_info'].get('name', 'N/A')}")
        response.append(f"টাইপ: {results['file_info'].get('extension', 'N/A')}")
        response.append(f"সাইজ: {results['file_info'].get('size_kb', 0)} KB")
        
        if results.get('passwords'):
            response.append("\n🔑 *পাসওয়ার্ড পাওয়া গেছে:*")
            for pwd in results['passwords'][:10]:
                response.append(f"• `{pwd}`")
        
        if results.get('api_keys'):
            response.append("\n🔐 *API Keys পাওয়া গেছে:*")
            for key in results['api_keys'][:10]:
                response.append(f"• `{key}`")
        
        if results.get('tokens'):
            response.append("\n🎫 *টোকেন পাওয়া গেছে:*")
            for token in results['tokens'][:10]:
                response.append(f"• `{token}`")
        
        if results.get('emails'):
            response.append("\n📧 *ইমেইল পাওয়া গেছে:*")
            for email in results['emails'][:10]:
                response.append(f"• `{email}`")
        
        if results.get('urls'):
            response.append("\n🌐 *URL পাওয়া গেছে:*")
            for url in results['urls'][:10]:
                response.append(f"• {url}")
        
        if results.get('functions'):
            response.append("\n⚙️ *ফাংশন পাওয়া গেছে:*")
            for func in results['functions'][:10]:
                response.append(f"• {func[0]}({func[1]})")
        
        if results.get('classes'):
            response.append("\n📦 *ক্লাস পাওয়া গেছে:*")
            for cls in results['classes'][:10]:
                response.append(f"• {cls}")
        
        if results.get('imports'):
            response.append("\n📥 *ইম্পোর্ট পাওয়া গেছে:*")
            for imp in results['imports'][:10]:
                response.append(f"• {imp}")
        
        if results.get('sensitive_data'):
            response.append("\n⚠️ *অন্যান্য সেনসিটিভ ডাটা:*")
            for data in results['sensitive_data'][:10]:
                response.append(f"• {data}")
        
        if not any([results.get('passwords'), results.get('api_keys'), results.get('sensitive_data')]):
            response.append("\n❌ কোনো সেনসিটিভ ডাটা পাওয়া যায়নি।")
        
        # Send code content
        if results.get('code_content'):
            code_file = f"code_{int(time.time())}.txt"
            with open(code_file, 'w', encoding='utf-8') as f:
                f.write(results['code_content'])
            
            with open(code_file, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"extracted_code_{file_name}.txt",
                    caption="📄 ফাইল থেকে এক্সট্রাক্ট করা কোড"
                )
            
            os.remove(code_file)
        
        # Send results
        full_response = "\n".join(response)
        if len(full_response) > 4000:
            parts = [full_response[i:i+4000] for i in range(0, len(full_response), 4000)]
            for i, part in enumerate(parts, 1):
                await update.message.reply_text(
                    f"*হ্যাকিং ফলাফল (পার্ট {i}/{len(parts)}):*\n\n{part}",
                    parse_mode='Markdown'
                )
        else:
            await update.message.reply_text(full_response, parse_mode='Markdown')
        
        # Cleanup
        os.remove(temp_path)
        user_states.pop(user_id, None)
    
    # Password Extractor from file
    elif state == 'waiting_extract':
        await update.message.reply_text(f"🔍 ফাইল থেকে ডাটা এক্সট্রাক্ট করা হচ্ছে...")
        
        content = file_bytes.decode('utf-8', errors='ignore')
        
        # Use Groq for smart extraction
        groq_results = groq_ai.extract_info_from_code(content)
        
        # Use local extractor
        extractor = AdvancedPasswordExtractor()
        local_results = extractor.extract_all_passwords(content)
        local_formatted = extractor.format_advanced_results(local_results)
        
        response = f"{local_formatted}\n\n🤖 *Groq AI Analysis:*\n{groq_results}"
        
        if len(response) > 4000:
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for i, part in enumerate(parts, 1):
                await update.message.reply_text(
                    f"*ফলাফল (পার্ট {i}/{len(parts)}):*\n\n{part}",
                    parse_mode='Markdown'
                )
        else:
            await update.message.reply_text(response, parse_mode='Markdown')
        
        user_states.pop(user_id, None)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    help_text = """
*🚀 সুপার অ্যাডভান্সড বট - হেল্প*

*কমান্ড:*
/start - বট শুরু করুন
/help - এই হেল্প দেখুন

*ফিচারসমূহ:*

🤖 *Groq AI Chat*
   • যেকোনো প্রশ্ন করুন
   • কোড জেনারেশন
   • টেকনিক্যাল সাপোর্ট

🔓 *File Hacker*
   • যেকোনো ফাইল হ্যাক
   • সব কোড বের করুন
   • পাসওয়ার্ড খুঁজুন

🔑 *Password Extractor*
   • হার্ডকোডেড পাসওয়ার্ড
   • API Keys বের করুন

📁 *File Generator*
   • কোড থেকে ফাইল বানান

🌐 *Website Downloader*
   • HTML ডাউনলোড

_শুধুমাত্র শিক্ষামূলক উদ্দেশ্যে!_
    """
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors"""
    logger.error(f"Update {update} caused error {context.error}")
    try:
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "❌ একটি ত্রুটি হয়েছে। আবার চেষ্টা করুন।\n"
                f"Error: {str(context.error)[:100]}"
            )
    except:
        pass

def main():
    """Main function to run the bot"""
    # Check requirements
    if not GROQ_AVAILABLE:
        print("⚠️ WARNING: Groq not installed. Run: pip install groq")

    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ ERROR: Please set your BOT_TOKEN in Environment Variables!")
        return

    # Create application
    application = Application.builder().token(BOT_TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_error_handler(error_handler)

    print("="*50)
    print("🚀 সুপার অ্যাডভান্সড বট চালু হচ্ছে...")
    print("="*50)
    
    # Render Web Service Setup
    # Render sets the PORT environment variable. We use webhook for web service.
    if 'RENDER' in os.environ or 'PORT' in os.environ:
        print("🌐 Web Service Mode (Render)")
        RENDER_EXTERNAL_URL = os.environ.get('RENDER_EXTERNAL_URL')
        if RENDER_EXTERNAL_URL:
            print(f"🔗 Webhook URL: {RENDER_EXTERNAL_URL}")
            application.run_webhook(
                listen="0.0.0.0",
                port=PORT,
                url_path=BOT_TOKEN,
                webhook_url=f"{RENDER_EXTERNAL_URL}/{BOT_TOKEN}"
            )
        else:
            print("⚠️ RENDER_EXTERNAL_URL not found, running polling...")
            application.run_polling(allowed_updates=Update.ALL_TYPES)
    else:
        print("💻 Local Polling Mode")
        application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
