import os
from typing import List, Dict, Optional

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("Warning: Groq library not available. Install with: pip install groq")

class GroqChatSummarizer:
    def __init__(self):
        self.fallback_summarizer = MockGroqChatSummarizer()  # Always have fallback available

        if not GROQ_AVAILABLE:
            self.client = None
            self.model = None
            print("Warning: Groq summarization disabled - library not available. Using mock summarizer.")
            return

        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            self.client = None
            self.model = None
            print("Warning: GROQ_API_KEY not found in environment variables. Using mock summarizer.")
            return

        try:
            # Initialize Groq client with current API
            self.client = Groq(api_key=api_key)

            # Try different models in order of preference
            models_to_try = [
                "llama-3.1-8b-instant",  # Fast and reliable
                "llama3-8b-8192",        # Standard model
                "mixtral-8x7b-32768",    # Alternative model
                "llama3-70b-8192"        # Larger model if available
            ]

            self.model = None
            for model in models_to_try:
                try:
                    # Test the model with a simple request
                    test_response = self.client.chat.completions.create(
                        messages=[{"role": "user", "content": "Hello"}],
                        model=model,
                        temperature=0.1,
                        max_tokens=5
                    )
                    self.model = model
                    print(f"Groq client initialized successfully with model: {model}")
                    print("Groq API connection verified successfully")
                    break
                except Exception as model_test_error:
                    print(f"Model {model} not available: {model_test_error}")
                    continue

            if self.model is None:
                print("Warning: No working Groq models found. Using mock summarizer.")
                self.client = None

        except Exception as e:
            print(f"Error initializing Groq client: {e}. Using mock summarizer.")
            self.client = None
            self.model = None
    
    def is_available(self):
        """Check if Groq service is available"""
        return self.client is not None and GROQ_AVAILABLE
    
    def prepare_messages_for_summary(self, messages: List[Dict], chat_type: str, chat_name: str) -> str:
        """
        Prepare messages for summarization by formatting them properly
        """
        if not messages:
            return ""
        
        # Format messages for better context
        formatted_messages = []
        for msg in messages:
            timestamp = msg.get('created_at', 'Unknown time')
            sender = msg.get('sender_username', 'Unknown user')
            text = msg.get('message_text', '')
            media = msg.get('media_filename', '')
            
            # Format message
            message_line = f"[{timestamp}] {sender}: {text}"
            if media:
                message_line += f" [Attached: {media}]"
            
            formatted_messages.append(message_line)
        
        # Create context header
        chat_context = f"{'Group' if chat_type == 'group' else 'Private'} Chat: {chat_name}\n"
        chat_context += f"Total Messages: {len(messages)}\n"
        chat_context += f"Date Range: {messages[0].get('created_at', 'Unknown')} to {messages[-1].get('created_at', 'Unknown')}\n"
        chat_context += "=" * 50 + "\n\n"
        
        return chat_context + "\n".join(formatted_messages)
    
    def generate_summary(self, messages: List[Dict], chat_type: str, chat_name: str, summary_length: str = "medium") -> Optional[str]:
        """
        Generate a summary of chat messages using Groq API or fallback to mock

        Args:
            messages: List of message dictionaries
            chat_type: "private" or "group"
            chat_name: Name of the chat/group
            summary_length: "short", "medium", or "detailed"

        Returns:
            Generated summary text or None if failed
        """
        if not self.is_available():
            # Use fallback summarizer
            return self.fallback_summarizer.generate_summary(messages, chat_type, chat_name, summary_length)

        try:
            if not messages:
                return "No messages to summarize."

            # Prepare messages text
            messages_text = self.prepare_messages_for_summary(messages, chat_type, chat_name)

            # Limit message length to prevent API limits
            if len(messages_text) > 8000:  # Conservative limit
                messages_text = messages_text[:8000] + "\n...[Message truncated due to length]"

            # Define summary length prompts
            length_prompts = {
                "short": "Provide a brief 2-3 sentence summary focusing on the main topics discussed.",
                "medium": "Provide a comprehensive summary in 1-2 paragraphs covering key topics, decisions, and important points.",
                "detailed": "Provide a detailed summary with multiple paragraphs covering all major topics, key decisions, important announcements, and notable conversations."
            }

            # Create the prompt
            system_prompt = f"""You are an AI assistant that creates helpful summaries of chat conversations.
            Analyze the following {'group' if chat_type == 'group' else 'private'} chat messages and create a summary.

            Instructions:
            - {length_prompts.get(summary_length, length_prompts['medium'])}
            - Focus on meaningful content and skip casual greetings
            - If there are important decisions, announcements, or conclusions, highlight them
            - Organize the summary logically by topics if multiple topics were discussed
            - Be objective and factual
            - If the chat contains mostly casual conversation, mention that
            - Preserve important dates, numbers, or specific details mentioned
            """

            user_prompt = f"Please summarize this chat conversation:\n\n{messages_text}"

            # Make API call to Groq with error handling
            try:
                chat_completion = self.client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    model=self.model,
                    temperature=0.3,  # Lower temperature for more consistent summaries
                    max_tokens=1000,  # Adjust based on your needs
                )

                return chat_completion.choices[0].message.content.strip()

            except Exception as api_error:
                print(f"Groq API error: {api_error}. Falling back to mock summarizer.")
                # Fallback to mock summarizer on API error
                return self.fallback_summarizer.generate_summary(messages, chat_type, chat_name, summary_length)

        except Exception as e:
            print(f"Error generating summary with Groq: {e}. Falling back to mock summarizer.")
            # Fallback to mock summarizer on any error
            return self.fallback_summarizer.generate_summary(messages, chat_type, chat_name, summary_length)
    
    def generate_summary_with_focus(self, messages: List[Dict], chat_type: str, chat_name: str, focus_areas: List[str] = None) -> Optional[str]:
        """
        Generate a summary with specific focus areas using Groq API or fallback to mock

        Args:
            messages: List of message dictionaries
            chat_type: "private" or "group"
            chat_name: Name of the chat/group
            focus_areas: List of specific areas to focus on (e.g., ["decisions", "action_items", "problems"])

        Returns:
            Generated summary text or None if failed
        """
        if not self.is_available():
            # Use fallback summarizer
            return self.fallback_summarizer.generate_summary_with_focus(messages, chat_type, chat_name, focus_areas)

        try:
            if not messages:
                return "No messages to summarize."

            messages_text = self.prepare_messages_for_summary(messages, chat_type, chat_name)

            # Limit message length to prevent API limits
            if len(messages_text) > 8000:
                messages_text = messages_text[:8000] + "\n...[Message truncated due to length]"

            focus_instruction = ""
            if focus_areas:
                focus_instruction = f"Pay special attention to: {', '.join(focus_areas)}. "

            system_prompt = f"""You are an AI assistant that creates focused summaries of chat conversations.
            Analyze the following {'group' if chat_type == 'group' else 'private'} chat messages and create a summary.

            Instructions:
            - {focus_instruction}Create a well-structured summary
            - Use bullet points or numbered lists when appropriate
            - Highlight key information, decisions, and action items
            - Include relevant dates and participants when important
            - Be concise but comprehensive
            """

            user_prompt = f"Please create a focused summary of this chat conversation:\n\n{messages_text}"

            try:
                chat_completion = self.client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    model=self.model,
                    temperature=0.3,
                    max_tokens=1200,
                )

                return chat_completion.choices[0].message.content.strip()

            except Exception as api_error:
                print(f"Groq API error in focused summary: {api_error}. Falling back to mock summarizer.")
                # Fallback to mock summarizer on API error
                return self.fallback_summarizer.generate_summary_with_focus(messages, chat_type, chat_name, focus_areas)

        except Exception as e:
            print(f"Error generating focused summary with Groq: {e}. Falling back to mock summarizer.")
            # Fallback to mock summarizer on any error
            return self.fallback_summarizer.generate_summary_with_focus(messages, chat_type, chat_name, focus_areas)

# Mock summarizer for testing when Groq is not available
class MockGroqChatSummarizer:
    def __init__(self):
        self.client = "mock"
        self.model = "mock-model"
        print("Mock Groq summarizer initialized for testing")
    
    def is_available(self):
        return True
    
    def prepare_messages_for_summary(self, messages: List[Dict], chat_type: str, chat_name: str) -> str:
        return f"Mock preparation for {len(messages)} messages in {chat_type} chat: {chat_name}"
    
    def generate_summary(self, messages: List[Dict], chat_type: str, chat_name: str, summary_length: str = "medium") -> str:
        return f"""
**AI Summary for {chat_name}**

This chat contains {len(messages)} messages in a {chat_type} conversation. The discussion covers various topics and interactions between participants.

**Key Highlights:**
• Multiple participants engaged in conversation
• Various topics were discussed
• Messages span across different time periods
• Both text and media content may be present

**Summary Length:** {summary_length}

**Note:** This is a mock summary for testing purposes. To enable real AI summarization, please configure your GROQ_API_KEY in the .env file.

**Chat Statistics:**
- Total messages: {len(messages)}
- Chat type: {chat_type}
- Chat name: {chat_name}
        """.strip()
    
    def generate_summary_with_focus(self, messages: List[Dict], chat_type: str, chat_name: str, focus_areas: List[str] = None) -> str:
        focus_text = f" with focus on: {', '.join(focus_areas)}" if focus_areas else ""
        return f"""
**Focused AI Summary for {chat_name}**

This is a focused summary{focus_text} for {len(messages)} messages in a {chat_type} chat.

**Analysis Overview:**
• Topic discussions and key themes
• Important decisions and action items  
• Notable announcements or updates
• Participant engagement patterns

**Focus Areas:** {', '.join(focus_areas) if focus_areas else 'General summary'}

**Mock Analysis Results:**
- Message patterns analyzed
- Key topics identified
- Participant interactions reviewed
- Timeline of discussions mapped

**Note:** This is a mock focused summary. Configure GROQ_API_KEY for real AI summarization.
        """.strip()