"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_dotnet import DotnetAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


SAMPLE = {'Sample.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n', 'UsersController.cs': '[ApiController]\n[Route("api/users")]\npublic class UsersController : ControllerBase\n{\n    [HttpGet("{id}")]\n    public IActionResult Get(int id) => Ok(id);\n}\n'}


def test_conforms_to_the_sdk(tmp_path: Path) -> None:
    for rel, text in SAMPLE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    _has_signals(assert_conforms(DotnetAnalyzer(), tmp_path))
