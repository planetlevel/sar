# Framework Definition Guide

This guide explains how to create a framework definition file for architecture analysis.

## Overview

Framework definition files use JSON format with a JSON Schema for validation and documentation. Each file defines:
- How to detect if a framework is present
- How to extract project metadata
- How to analyze architectural patterns

## Complete Structure Tree

```
SAMPLE_FRAMEWORK
├── detection (answers: "Is this framework present?")
│   ├── binaries (type: filename)
│   │   └── patterns: ["sample-framework.jar", "sample-*.jar"]
│   │
│   ├── files (type: filename)
│   │   └── patterns: ["sample-config.xml", "application.properties"]
│   │
│   ├── dependencies
│   │   ├── pom.xml (type: filecontent, search_type: xml_element)
│   │   └── build.gradle (type: filecontent, search_type: regex)
│   │
│   ├── imports (type: joern, search_type: import)
│   │   └── patterns: ["com.example.sample.*", "com.example.sample.annotations.*"]
│   │
│   ├── annotations (type: joern, search_type: annotation_name)
│   │   └── patterns: ["com.example.sample.Controller", "com.example.sample.Service"]
│   │
│   └── code_patterns (type: joern, search_type: class_name_regex)
│       └── patterns: [".*SampleController", ".*SampleService"]
│
├── metadata (answers: "What is the project info?")
│   ├── project_name (type: filecontent, search_type: xml_element)
│   ├── project_version (type: filecontent, search_type: xml_element)
│   ├── contacts (type: filecontent, search_type: regex)
│   ├── repo_url (type: filecontent, search_type: xml_element)
│   ├── license (type: filecontent, search_type: xml_element)
│   └── organization (type: filecontent, search_type: xml_element)
│
└── architecture (answers: "How is the code structured?")
    ├── database
    │   ├── repository_pattern (type: joern, search_type: class_name_regex)
    │   ├── operation_methods (type: joern, search_type: method_name_regex)
    │   └── query_methods (type: joern, search_type: method_signature)
    │       └── signatures: [...]
    │
    ├── danger
    │   ├── process (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── reflection (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── deserialization (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── filesystem (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── xpath (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── ldap (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── xml (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── expression_parsing (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   └── template_rendering (type: joern, search_type: method_signature)
    │       └── signatures: [...]
    │
    ├── data_flow
    │   ├── sources (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   └── propagators (type: joern, search_type: method_signature)
    │       └── signatures: [...]
    │
    ├── defense
    │   ├── sanitizer (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── authentication (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── authorization (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── cryptography (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   └── logging (type: joern, search_type: method_signature)
    │       └── signatures: [...]
    │
    ├── communication
    │   ├── socket (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   ├── http (type: joern, search_type: method_signature)
    │   │   └── signatures: [...]
    │   └── rest (type: joern, search_type: method_signature)
    │       └── signatures: [...]
    │
    └── routing
        ├── handler_classes
        │   ├── class_pattern (type: joern, search_type: class_name_regex)
        │   │   └── pattern: ".*Controller|.*Handler|.*Resource|.*Endpoint"
        │   │
        │   └── annotations (type: joern, search_type: annotation_name)
        │       └── patterns: ["Controller", "RestController", "RequestMapping"]
        │
        ├── route_definitions
        │   ├── annotations (type: joern, search_type: annotation_name_regex)
        │   │   └── pattern: ".*Mapping|.*Route|.*Path"
        │   │
        │   └── http_methods (type: joern, search_type: annotation_name_regex)
        │       └── patterns: {get, post, put, delete}
        │
        └── parameters (type: joern, search_type: annotation_name_regex)
            └── patterns: {path_variable, query_param, request_body}
```

## File Structure

```json
{
  "$schema": "../schema/framework-schema.json",
  "name": "Framework Name",
  "extends": "base_language",
  "languages": ["language1", "language2"],

  "detection": { ... },
  "metadata": { ... },
  "architecture": { ... }
}
```

---

## 1. Basic Information

### `name` (required)
The display name of the framework.
```json
"name": "Spring Boot"
```

### `extends` (optional)
Base language or framework this extends. Common values: `"java"`, `"javascript"`, `"python"`.
```json
"extends": "java"
```

### `languages` (required)
Array of programming languages this framework supports.
```json
"languages": ["java", "kotlin"]
```

---

## 2. Detection Section

**Purpose**: Answers "Is this framework present in the codebase?"

Detection runs in priority order:
1. **binaries** - Compiled files or JARs (highest priority)
2. **files** - Configuration or framework-specific files
3. **dependencies** - Package manager dependencies
4. **imports** - Import statements in code
5. **annotations** - Framework annotations
6. **code_patterns** - Class naming patterns (lowest priority)

### Pattern Types

#### Filename Patterns
Search for files by name (supports wildcards).
```json
"binaries": {
  "type": "filename",
  "patterns": [
    "spring-boot.jar",
    "spring-*.jar"
  ]
}
```

#### Dependency Patterns
Search in `pom.xml`, `build.gradle`, `package.json`, etc.
```json
"dependencies": {
  "pom.xml": [
    {
      "type": "filecontent",
      "search_type": "xml_element",
      "pattern": "artifactId",
      "value": "spring-boot-starter",
      "library": "Spring Boot"
    }
  ],
  "build.gradle": [
    {
      "type": "filecontent",
      "search_type": "regex",
      "pattern": "org\\.springframework\\.boot",
      "library": "Spring Boot"
    }
  ]
}
```

#### Joern Patterns
Use Joern code analysis for imports, annotations, and code patterns.
```json
"imports": {
  "type": "joern",
  "search_type": "import",
  "patterns": [
    "org.springframework.boot.*",
    "org.springframework.web.*"
  ]
},

"annotations": {
  "type": "joern",
  "search_type": "annotation_name",
  "patterns": [
    "org.springframework.boot.SpringBootApplication",
    "org.springframework.stereotype.Controller"
  ]
},

"code_patterns": {
  "type": "joern",
  "search_type": "class_name_regex",
  "patterns": [
    ".*Application",
    ".*Config"
  ]
}
```

---

## 3. Metadata Section

**Purpose**: Answers "What is the project information?"

Extract project metadata from files like `pom.xml`, `package.json`, `README.md`, etc.

```json
"metadata": {
  "project_name": {
    "type": "filecontent",
    "search_type": "xml_element",
    "files": ["pom.xml"],
    "pattern": "name"
  },
  "project_version": {
    "type": "filecontent",
    "search_type": "xml_element",
    "files": ["pom.xml"],
    "pattern": "version"
  },
  "contacts": {
    "type": "filecontent",
    "search_type": "regex",
    "files": ["README.md", "MAINTAINERS.md"],
    "pattern": "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})"
  },
  "repo_url": {
    "type": "filecontent",
    "search_type": "xml_element",
    "files": ["pom.xml"],
    "pattern": "url"
  }
}
```

---

## 4. Architecture Section

**Purpose**: Answers "How is the code structured?"

This is where you define the architectural patterns to analyze. Use technology-agnostic category names.

### Common Categories

#### database
Patterns for data persistence operations.
```json
"database": {
  "repository_pattern": {
    "type": "joern",
    "search_type": "class_name_regex",
    "pattern": ".*Repository.*|.*DAO.*|.*DataAccess.*"
  },
  "operation_methods": {
    "type": "joern",
    "search_type": "method_name_regex",
    "pattern": "save|persist|insert|update|find.*|delete.*"
  },
  "query_methods": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "java.sql.Statement.execute:boolean(java.lang.String)",
      "java.sql.PreparedStatement.executeQuery:java.sql.ResultSet()"
    ]
  }
}
```

#### danger
Potentially dangerous operations that accept user input.
```json
"danger": {
  "process": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
      "java.lang.ProcessBuilder.start:java.lang.Process()"
    ]
  },
  "reflection": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "java.lang.Class.forName:java.lang.Class(java.lang.String)"
    ]
  },
  "filesystem": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "java.io.File.<init>:void(java.lang.String)",
      "java.nio.file.Paths.get:java.nio.file.Path(java.lang.String,java.lang.String[])"
    ]
  }
}
```

#### data_flow
Sources of external input.
```json
"data_flow": {
  "sources": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "javax.servlet.http.HttpServletRequest.getParameter:java.lang.String(java.lang.String)",
      "javax.servlet.http.HttpServletRequest.getHeader:java.lang.String(java.lang.String)"
    ]
  }
}
```

#### defense
Security controls and protective measures.
```json
"defense": {
  "sanitizer": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "org.owasp.encoder.Encode.forHtml:java.lang.String(java.lang.String)"
    ]
  },
  "authentication": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "javax.servlet.http.HttpServletRequest.getUserPrincipal:java.security.Principal()"
    ]
  },
  "cryptography": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "javax.crypto.Cipher.getInstance:javax.crypto.Cipher(java.lang.String)"
    ]
  }
}
```

#### communication
Network and inter-process communication.
```json
"communication": {
  "http": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "java.net.URL.openConnection:java.net.URLConnection()",
      "java.net.HttpURLConnection.connect:void()"
    ]
  },
  "socket": {
    "type": "joern",
    "search_type": "method_signature",
    "signatures": [
      "java.net.Socket.<init>:void(java.lang.String,int)"
    ]
  }
}
```

#### routing
HTTP routing layer that maps URL patterns to code entry points (for web frameworks).
```json
"routing": {
  "handler_classes": {
    "class_pattern": {
      "type": "joern",
      "search_type": "class_name_regex",
      "pattern": ".*Controller|.*Handler|.*Resource|.*Endpoint"
    },
    "annotations": {
      "type": "joern",
      "search_type": "annotation_name",
      "patterns": [
        "Controller",
        "RestController",
        "RequestMapping"
      ]
    }
  },
  "route_definitions": {
    "annotations": {
      "type": "joern",
      "search_type": "annotation_name_regex",
      "pattern": ".*Mapping|.*Route|.*Path"
    },
    "http_methods": {
      "type": "joern",
      "search_type": "annotation_name_regex",
      "patterns": {
        "get": "GetMapping|GET|Get",
        "post": "PostMapping|POST|Post",
        "put": "PutMapping|PUT|Put",
        "delete": "DeleteMapping|DELETE|Delete"
      }
    }
  },
  "parameters": {
    "type": "joern",
    "search_type": "annotation_name_regex",
    "patterns": {
      "path_variable": "PathVariable|PathParam",
      "query_param": "RequestParam|QueryParam",
      "request_body": "RequestBody|Body"
    }
  }
}
```

The `routing` category consolidates what were previously separate `endpoints` and `controllers` sections:
- **handler_classes**: Classes that contain route handlers (Controllers, Resources, Handlers)
- **route_definitions**: Annotations that define URL routes and HTTP methods
- **parameters**: Annotations that bind request data to method parameters

---

## Pattern Types Reference

### Search Types for `type: "joern"`

- **`method_signature`**: Exact method signatures
  - Format: `package.class.method:returnType(paramType1,paramType2)`
  - Use `signatures` array for multiple

- **`method_name_regex`**: Method names matching regex
  - Use `pattern` for single pattern

- **`class_name_regex`**: Class names matching regex
  - Use `pattern` for single pattern

- **`annotation_name`**: Exact annotation names
  - Use `patterns` array for multiple

- **`annotation_name_regex`**: Annotation names matching regex
  - Use `pattern` for single pattern

- **`import`**: Import statements
  - Use `patterns` array for multiple

### Search Types for `type: "filecontent"`

- **`regex`**: Regular expression search
  - Optional `group` field to extract capture group

- **`xml_element`**: XPath-like element search
  - `pattern` is the element path (e.g., `"license/name"`)

- **`xpath`**: Full XPath query
  - Use `query` field instead of `pattern`

- **`yaml_path`**: YAML path query
  - Use `path` field (e.g., `"spring.datasource.url"`)

- **`json_value`**: JSON path query
  - Use `path` field (e.g., `"dependencies.lodash"`)

### Search Types for `type: "filename"`

- **No search_type needed**: Just list filename patterns
  - Supports wildcards (`*`)

---

## Pattern Consolidation

When multiple patterns share the same `type` and `search_type`, consolidate them:

**Instead of:**
```json
"imports": [
  { "type": "joern", "search_type": "import", "pattern": "org.springframework.*" },
  { "type": "joern", "search_type": "import", "pattern": "org.springframework.boot.*" }
]
```

**Use:**
```json
"imports": {
  "type": "joern",
  "search_type": "import",
  "patterns": [
    "org.springframework.*",
    "org.springframework.boot.*"
  ]
}
```

For method signatures, use `signatures` instead of `patterns`:
```json
"process": {
  "type": "joern",
  "search_type": "method_signature",
  "signatures": [
    "java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
    "java.lang.ProcessBuilder.start:java.lang.Process()"
  ]
}
```

---

## Complete Architecture Category Reference

This section documents all available architecture categories across all framework definitions. These categories are dynamically discovered from framework JSON files - nothing is hardcoded.

### Category Tree

All categories are "behaviors" - patterns that describe how code behaves. The top-level categories group related behaviors:

```
📁 communication/
  ├─ apache_http/                    # Apache HttpClient calls
  ├─ http/                           # Generic HTTP connections (URLConnection, etc.)
  ├─ rest/                           # REST API calls (RestTemplate, etc.)
  ├─ socket/                         # Socket connections
  └─ webclient/                      # Reactive WebClient

📁 danger/
  ├─ deserialization/                # Object deserialization (readObject, etc.)
  ├─ expression_parsing/             # Expression evaluation (SpEL, OGNL, etc.)
  ├─ filesystem/                     # File operations (File, FileInputStream, etc.)
  ├─ ldap/                           # LDAP queries
  ├─ process/                        # Process execution (Runtime.exec, ProcessBuilder)
  ├─ reflection/                     # Reflection APIs (Class.forName, Method.invoke)
  ├─ template_rendering/             # Template rendering (potential SSTI)
  ├─ xml/                            # XML parsing
  └─ xpath/                          # XPath queries

📁 data_flow/
  ├─ sources/                        # Data sources (request params, headers, cookies)
  └─ propagators/                    # Data transformation/propagation (decode, toLowerCase)

📁 database/
  ├─ entity_extraction/              # Configuration for extracting entity names
  │  ├─ dao_suffix                   # Suffix for DAO classes (e.g., "DAO")
  │  └─ repository_suffix            # Suffix for Repository classes
  ├─ operation_categories/           # CRUD operation categorization
  │  ├─ create                       # Create operations (save, persist, insert)
  │  ├─ delete                       # Delete operations (delete, remove)
  │  ├─ read                         # Read operations (find, select, get)
  │  └─ update                       # Update operations (update, modify)
  ├─ operation_methods/              # Database method name patterns
  ├─ query_methods/                  # Direct SQL query methods
  └─ repository_pattern/             # Repository/DAO class patterns

📁 defense/
  ├─ authentication/                 # Authentication operations
  ├─ authorization/                  # Authorization checks
  ├─ crypto/                         # Cryptographic operations
  ├─ cryptography/                   # Alternative crypto category
  ├─ logging/                        # Logging operations
  └─ sanitizer/                      # Input sanitization/validation

📁 routing/
  ├─ handler_classes/                # Controller/Handler class patterns
  │  ├─ annotations                  # Handler annotations (@Controller, etc.)
  │  └─ class_pattern                # Class name patterns (*Controller, *Handler)
  ├─ parameters/                     # Route parameter extraction
  │  ├─ form_binding                 # Form data binding (@ModelAttribute)
  │  ├─ path_variable                # Path variables (@PathVariable)
  │  ├─ query_param                  # Query parameters (@RequestParam)
  │  └─ request_body                 # Request body (@RequestBody)
  └─ route_definitions/              # Route definitions
     ├─ annotations                  # Route annotations (@RequestMapping)
     ├─ files                        # File-based routing (routes.rb, urls.py)
     └─ http_methods                 # HTTP method mappings
```

### Report Display

**HTML Viewer**: Groups behaviors by top-level category in this order:
1. **routing** - Request routing patterns
2. **defense** - Security controls
3. **data_flow** - Data sources and propagation
4. **danger** - Potentially risky operations
5. **database** - Database patterns
6. **communication** - External communication

**Endpoints Table**: Groups behaviors into 4 columns:
1. **Dangerous Ops**: `danger_*` - Risky operations requiring validation
2. **Data Flow**: `data_flow_*` - Sources and propagators
3. **Defenses**: `defense_*` - Security controls
4. **Framework Features**: `routing_*`, `communication_*`, `database_*`

### Adding New Categories

You can add new categories at any level in the tree. The architecture agent will automatically discover and analyze them. Category names should:
- Be descriptive and technology-agnostic
- Use underscores for multi-word names
- Start with prefix indicating purpose (`danger_`, `defense_`, `data_flow_`, etc.)

---

## Important Notes

### NOT for Vulnerability Detection
This tool analyzes **architecture**, not vulnerabilities. Avoid words like:
- ❌ "injection", "traversal", "weak", "insecure"
- ✅ Use neutral terms: "process", "filesystem", "reflection"

### Technology-Agnostic Names
Use generic category names, not technology-specific:
- ❌ `jdbc_methods`, `hibernate_operations`
- ✅ `query_methods`, `persistence_operations`

### Method Signature Format
Full signature format for Joern:
```
package.class.method:returnType(paramType1,paramType2)
```

Examples:
- `java.sql.Statement.execute:boolean(java.lang.String)`
- `javax.servlet.http.HttpServletRequest.getParameter:java.lang.String(java.lang.String)`
- `java.io.File.<init>:void(java.lang.String)`

---

## Example: Creating a New Framework

See `SAMPLE_FRAMEWORK.json` for a complete working example with all pattern types demonstrated.
