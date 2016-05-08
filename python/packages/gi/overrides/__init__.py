# support overrides in different directories than our gi module
from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)
