from enum import StrEnum

from pydantic import BaseModel


class StrideCategory(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class Difficulty(StrEnum):
    """How much knowledge a threat requires to be found.

    - EASY:   derivable from a single component/flow attribute
              (e.g. ``encrypted=false`` -> information disclosure).
    - MEDIUM: requires the relationship or trust-boundary context between
              components (e.g. a shared cache, a flow to a third party).
    - HARD:   requires implicit security knowledge or configuration/permission
              reasoning that is not expressed as a simple attribute
              (e.g. a public storage bucket, an over-broad IAM role).
    """

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class Threat(BaseModel):
    id: str
    component_id: str | None = None
    data_flow_id: str | None = None
    category: StrideCategory
    description: str
    mitigation: str
    difficulty: Difficulty | None = None