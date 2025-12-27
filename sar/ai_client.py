#!/usr/bin/env python3
"""
AI Client - Centralized Claude API client for Compass

Provides a unified interface for calling Claude via AWS Bedrock or Anthropic API.
All Compass tools should use this client for AI operations.
"""

import json
import os
from typing import Optional, Dict, Any


# Global AI usage tracker (singleton pattern)
_global_ai_tracker = None


def get_global_ai_tracker():
    """Get the global AI usage tracker (creates if needed)"""
    global _global_ai_tracker
    if _global_ai_tracker is None:
        _global_ai_tracker = {
            'calls': 0,
            'input_tokens': 0,
            'output_tokens': 0,
            'total_cost': 0.0
        }
    return _global_ai_tracker


def print_ai_usage_summary(tool_name: str = "Compass"):
    """Print AI usage summary for the current session

    Args:
        tool_name: Name of the tool to display in summary
    """
    tracker = get_global_ai_tracker()

    total_tokens = tracker['input_tokens'] + tracker['output_tokens']

    print(f"\n{'='*60}")
    print(f"AI USAGE SUMMARY - {tool_name}")
    print(f"{'='*60}")

    if tracker['calls'] == 0:
        print("No AI calls made (--simple-purposes mode or no AI features used)")
    else:
        print(f"Total AI calls:     {tracker['calls']}")
        print(f"Input tokens:       {tracker['input_tokens']:,}")
        print(f"Output tokens:      {tracker['output_tokens']:,}")
        print(f"Total tokens:       {total_tokens:,}")
        print(f"Total cost:         ${tracker['total_cost']:.4f}")

    print(f"{'='*60}\n")


class AIClient:
    """Unified Claude API client supporting Bedrock and Anthropic"""

    # Claude 3.5 Sonnet v2 pricing (per million tokens)
    PRICING = {
        'input': 3.00,   # $3.00 per 1M input tokens
        'output': 15.00  # $15.00 per 1M output tokens
    }

    def __init__(self, use_bedrock: bool = True, debug: bool = False):
        """
        Initialize AI client

        Args:
            use_bedrock: If True, try AWS Bedrock first (default: True)
            debug: Enable debug output
        """
        self.debug = debug
        self.bedrock_client = None
        self.anthropic_client = None

        # Track token usage and costs
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.call_count = 0

        # Try to initialize Bedrock client first
        if use_bedrock:
            try:
                import boto3
                self.bedrock_client = boto3.client('bedrock-runtime', region_name='us-east-1')
                if debug:
                    print("[AI CLIENT] Initialized Bedrock client")
            except Exception as e:
                if debug:
                    print(f"[AI CLIENT] Bedrock not available: {e}")

        # Initialize Anthropic client as fallback
        if not self.bedrock_client:
            api_key = os.environ.get('ANTHROPIC_API_KEY')
            if api_key:
                try:
                    from anthropic import Anthropic
                    self.anthropic_client = Anthropic(api_key=api_key)
                    if debug:
                        print("[AI CLIENT] Initialized Anthropic API client")
                except Exception as e:
                    if debug:
                        print(f"[AI CLIENT] Anthropic client not available: {e}")

    def is_available(self) -> bool:
        """Check if any AI client is available"""
        return self.bedrock_client is not None or self.anthropic_client is not None

    def test_connection(self) -> bool:
        """Test AI connection with a minimal call to verify authentication

        Returns:
            True if connection works, False otherwise

        Raises:
            RuntimeError: If connection test fails with auth error
        """
        if not self.is_available():
            raise RuntimeError("No AI client available (Bedrock or Anthropic API)")

        if self.debug:
            print("[AI CLIENT] Testing connection with minimal prompt...")

        try:
            # Minimal test prompt (costs ~$0.0001)
            response = self.call_claude("Say 'OK'", max_tokens=10, temperature=0)

            if self.debug:
                print(f"[AI CLIENT] Connection test successful: {response}")

            return True
        except Exception as e:
            error_msg = str(e)

            # Check for auth-related errors
            if any(keyword in error_msg.lower() for keyword in ['auth', 'credential', 'permission', 'unauthorized', 'forbidden', 'access denied']):
                raise RuntimeError(f"AI authentication failed: {error_msg}")

            # Other errors
            raise RuntimeError(f"AI connection test failed: {error_msg}")

    def call_claude(self, prompt: str, max_tokens: int = 4096, temperature: float = 0.3) -> str:
        """
        Call Claude with the given prompt

        Args:
            prompt: The prompt to send to Claude
            max_tokens: Maximum tokens in response (default: 4096)
            temperature: Temperature for sampling (default: 0.3)

        Returns:
            Response text from Claude

        Raises:
            RuntimeError: If no AI client is available
        """
        if not self.is_available():
            raise RuntimeError("No AI client available (Bedrock or Anthropic API)")

        if self.debug:
            client_type = "Bedrock" if self.bedrock_client else "Anthropic API"
            print(f"[AI CLIENT] Calling Claude via {client_type}...")

        # Try Bedrock first
        if self.bedrock_client:
            return self._call_bedrock(prompt, max_tokens, temperature)
        else:
            return self._call_anthropic(prompt, max_tokens, temperature)

    def _call_bedrock(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Call AWS Bedrock Claude"""
        # Prepare request for Bedrock
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        })

        # Call Bedrock with cross-region inference profile
        response = self.bedrock_client.invoke_model(
            modelId="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
            body=body
        )

        # Parse response
        response_body = json.loads(response['body'].read())
        response_text = response_body['content'][0]['text'].strip()

        # Extract token usage
        usage = response_body.get('usage', {})
        input_tokens = usage.get('input_tokens', 0)
        output_tokens = usage.get('output_tokens', 0)

        # Track and display usage
        self._track_usage(input_tokens, output_tokens, "Bedrock")

        return response_text

    def _call_anthropic(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Call Anthropic API directly"""
        response = self.anthropic_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )

        response_text = response.content[0].text.strip()

        # Extract token usage
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

        # Track and display usage
        self._track_usage(input_tokens, output_tokens, "Anthropic API")

        return response_text

    def _track_usage(self, input_tokens: int, output_tokens: int, source: str):
        """Track token usage and display cost information"""
        # Update instance totals
        self.call_count += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

        # Calculate costs (per million tokens)
        input_cost = (input_tokens / 1_000_000) * self.PRICING['input']
        output_cost = (output_tokens / 1_000_000) * self.PRICING['output']
        call_cost = input_cost + output_cost
        self.total_cost += call_cost

        # Update global tracker
        global_tracker = get_global_ai_tracker()
        global_tracker['calls'] += 1
        global_tracker['input_tokens'] += input_tokens
        global_tracker['output_tokens'] += output_tokens
        global_tracker['total_cost'] += call_cost

        # Display this call's usage
        total_tokens = input_tokens + output_tokens
        print(f"[AI TOKENS] {source}: {input_tokens:,} in + {output_tokens:,} out = {total_tokens:,} tokens")
        print(f"[AI COST] This call: ${call_cost:.4f} (in: ${input_cost:.4f}, out: ${output_cost:.4f})")

        # Display cumulative usage
        cumulative_total = self.total_input_tokens + self.total_output_tokens
        print(f"[AI TOTAL] Session: {self.call_count} calls, {cumulative_total:,} tokens, ${self.total_cost:.4f}")

    def get_usage_summary(self) -> Dict[str, Any]:
        """Get summary of token usage and costs

        Returns:
            Dictionary with usage statistics
        """
        return {
            'calls': self.call_count,
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens,
            'total_tokens': self.total_input_tokens + self.total_output_tokens,
            'total_cost': self.total_cost
        }


def main():
    """Test the AI client"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: ai_client.py <prompt>")
        print("\nExample:")
        print("  python3 -m compass.ai_client 'What is 2+2?'")
        sys.exit(1)

    prompt = sys.argv[1]

    client = AIClient(debug=True)

    if not client.is_available():
        print("ERROR: No AI client available")
        print("  - For Bedrock: Configure AWS credentials")
        print("  - For Anthropic API: Set ANTHROPIC_API_KEY environment variable")
        sys.exit(1)

    response = client.call_claude(prompt)

    print("\n=== Response ===")
    print(response)


if __name__ == "__main__":
    main()
