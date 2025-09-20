from ollama import Client


class OllamaModel:
    def __init__(self, model: str):
        self.model = model
        self.client = Client()  # Ollama client

    def generate(self, messages: list) -> str:
        """
        Call Ollama chat with messages = [{"role":"system|user|assistant", "content":"..."}].
        Returns the assistant content string.
        """
        try:
            response = self.client.chat(model=self.model, messages=messages)
            # Expected dict shape
            if isinstance(response, dict) and 'message' in response:
                msg = response.get('message') or {}
                if isinstance(msg, dict):
                    return msg.get('content', '')
                # message as object
                if hasattr(msg, 'content'):
                    return getattr(msg, 'content') or ''

            # Object shape with .message
            if hasattr(response, 'message'):
                msg = getattr(response, 'message')
                if isinstance(msg, dict):
                    return msg.get('content', '')
                if hasattr(msg, 'content'):
                    return getattr(msg, 'content') or ''

            # Fallback
            return str(response)
        except Exception as e:
            # Surface a concise error so the agent can handle it
            return f"{ { 'error': f'Ollama chat failed: {e}' } }"


class SecurityAgent:
    def __init__(self, llm: OllamaModel, tools: list):
        self.llm = llm
        self.tools = tools
        self.memory = []

        self.system_prompt = (
            "You are a security analysis agent. "
            "You have access to the following tools:\n" +
            "\n".join([f"- {tool['name']}: {tool['description']}" for tool in tools]) +
            "\nUse these tools to analyze and respond to security-related tasks."
        )


