# Licify - Biblioteca Java para Gestión de Licencias

## Descripción
Licify es una biblioteca Java robusta para la gestión de licencias de software, que proporciona funcionalidades avanzadas de encriptación híbrida, firmas digitales, validación de hardware y múltiples formatos de serialización.

## Estado Actual
- ✅ **Tests**: 27/27 pasando (100% éxito)
- ✅ **Compilación**: BUILD SUCCESS
- ✅ **Cobertura**: Reportes JaCoCo generados
- ✅ **GitHub**: Repositorio sincronizado

## Características Principales

### 🔒 Encriptación Híbrida
- Combinación de algoritmos simétricos (AES) y asimétricos (RSA)
- Configuración flexible de parámetros de seguridad
- Soporte para múltiples tamaños de clave

### ✍️ Firmas Digitales
- Validación criptográfica de integridad
- Configuración personalizable de algoritmos
- Verificación automática de autenticidad

### 🖥️ Identificación de Hardware
- Binding de licencias a hardware específico
- Múltiples componentes de hardware analizados
- Respaldo de configuración de hardware

### 📝 Múltiples Formatos
- BINARIO: Para máxima eficiencia
- STRING: Para legibilidad humana
- XML: Para interoperabilidad
- PROPERTIES: Para configuración

### 🧬 Generación de Semillas
- Semillas criptográficas determinísticas
- Múltiples algoritmos de hash (SHA-256/384/512)
- Entropía del sistema incluida

## Estructura del Proyecto

```
Licify/
├── src/
│   ├── main/java/com/licify/
│   │   ├── Licify.java              # API principal
│   │   ├── LicenseKeyPair.java      # Gestión de claves
│   │   ├── SeedGenerator.java       # Semillas criptográficas
│   │   ├── core/                    # Funcionalidades centrales
│   │   ├── encryption/              # Encriptación híbrida
│   │   ├── signing/                 # Firmas digitales
│   │   ├── hardware/                # Identificación HW
│   │   ├── io/                      # Formatos E/S
│   │   ├── util/                    # Utilidades
│   │   └── exception/               # Excepciones
│   └── test/java/com/licify/
│       └── LicifyTest.java          # Suite de tests
├── target/                          # Archivos compilados
├── pom.xml                          # Configuración Maven
└── module-info.java                 # Definición de módulo
```

## Inicio Rápido

### Prerequisitos
- Java 17 o superior
- Maven 3.8 o superior

### Compilación
```bash
mvn clean compile
```

### Ejecución de Tests
```bash
mvn test
```

### Compilación y Tests
```bash
mvn clean install
```

## Ejemplos de Uso

### Crear una Licencia
```java
Licify licify = new Licify();

// Crear licencia básica
License license = licify.createLicense()
    .withProductName("Mi Producto")
    .withVersion("1.0.0")
    .withUserId("usuario123")
    .withExpiryDate(LocalDateTime.now().plusYears(1))
    .build();

// Guardar licencia
licify.saveLicense(license, "mi_licencia.lic", IOFormat.BINARY);
```

### Validar una Licencia
```java
License license = licify.loadLicense("mi_licencia.lic", IOFormat.BINARY);
ValidationResult result = licify.validateLicense(license);
if (result.isValid()) {
    System.out.println("Licencia válida");
} else {
    System.out.println("Licencia inválida: " + result.getErrors());
}
```

### Encriptar Datos
```java
HybridEncryptionResult result = licify.encryptData("datos sensibles");
String encryptedData = result.getEncryptedData();
String decryptionKey = result.getDecryptionKey();
```

## Tests y Calidad

### Cobertura de Tests
- **Total**: 27 tests
- **Éxito**: 27 tests
- **Fallos**: 0 tests
- **Tiempo**: 6.559s

### Reportes Generados
- `target/surefire-reports/` - Reportes de tests
- `target/site/jacoco/` - Análisis de cobertura HTML
- `target/jacoco.exec` - Datos de ejecución

## Configuración Maven

### Dependencia
```xml
<dependency>
    <groupId>com.licify</groupId>
    <artifactId>licify</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Plugins Configurados
- **Maven Compiler Plugin**: Java 17
- **Maven Surefire Plugin**: Ejecución de tests
- **JaCoCo Plugin**: Análisis de cobertura
- **Maven JAR Plugin**: Empaquetado

## Correcciones Recientes

### Test `testGenerateSeed`
- ✅ **Corregido**: Validación de semillas criptográficas en lugar de texto plano
- **Impacto**: Tests ahora validan propiedades criptográficas apropiadas

### Test `testSaveAndLoadString`
- ✅ **Corregido**: Eliminación de NoSuchFileException
- **Solución**: Cambio de Files.write() a FileOutputStream + BufferedWriter
- **Impacto**: Formato STRING ahora funciona correctamente

## Assets Disponibles

1. **`Licify-Fuente-Completo.zip`** - Código fuente completo con correcciones
2. **`Licify-Codigo-Java.zip`** - Solo código Java y configuración esencial
3. **`Licify-Dependencias-Compiladas.zip`** - Archivos compilados y reportes
4. **`ASSETS-DOCUMENTACION.md`** - Documentación completa de assets

## Repositorio
- **GitHub**: https://github.com/yasmramos/Licify
- **Estado**: Sincronizado con últimas correcciones

## Licencia
Proyecto de código abierto para fines educativos y de desarrollo.

---

**Desarrollado por MiniMax Agent** - Asistente de desarrollo IA especializado en proyectos Java