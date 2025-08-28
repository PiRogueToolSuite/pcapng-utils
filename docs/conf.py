# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import sys
from pathlib import Path

# sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.append(str(Path("_ext").resolve()))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "PCAPNG-utils"
copyright = "2025, Defensive Lab Agency"

autodoc_pydantic_model_show_json = False
autodoc_pydantic_model_show_validator_summary = True
autodoc_pydantic_settings_show_json = False
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autoclass_content = "class"
autodoc_member_order = "groupwise"

autodoc_pydantic_model_show_field_summary = True
autodoc_pydantic_field_show_constraints = True
autodoc_pydantic_model_signature_prefix = "class"
autodoc_pydantic_field_show_required = True
autodoc_pydantic_model_member_order = "bysource"

extensions = [
    "myst_parser",
    "sphinx_toolbox.collapse",
    "sphinx_toolbox.formatting",
    "sphinx.ext.autodoc",
    "sphinx.ext.autodoc.typehints",
    "sphinx_copybutton",
    "sphinx_rtd_theme",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.githubpages",
    "sphinxcontrib.autodoc_pydantic",
    "sphinxcontrib.datatemplates",
]

templates_path = ["_templates"]
html_static_path = ["_static"]
html_theme = "sphinx_rtd_theme"
html_logo = "_static/pts_logo.png"
html_theme_options = {
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": False,
    "vcs_pageview_mode": "",
    "flyout_display": "hidden",
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "titles_only": False,
}
html_css_files = [
    "css/table-fix.css",
    "css/theme-extra.css",
]

viewcode_line_numbers = True

napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_preprocess_types = True
napoleon_use_param = True

exclude_patterns = []

autosummary_generate = True

intersphinx_mapping = {
    "pydantic": ("https://docs.pydantic.dev/latest", None),
    "jinja2": ("https://jinja.palletsprojects.com/en/stable", None),
    "python": ("https://docs.python.org/3", None),
}
