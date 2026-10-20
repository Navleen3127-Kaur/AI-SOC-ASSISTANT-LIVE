import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture(autouse=True)
def mock_llm():
    with patch("soc_analyst.agents.soc_analyst.get_llm") as mock_get:
        mock_model = MagicMock()
        mock_model.invoke.side_effect = Exception("Mock LLM offline")
        mock_get.return_value = mock_model
        yield mock_model
