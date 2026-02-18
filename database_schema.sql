-- GEPI Database Schema
-- Fecha: 2026-02-16

-- Crear la base de datos
CREATE DATABASE IF NOT EXISTS gepi_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE gepi_db;

-- =======================
-- Tabla: users (Inspectores)
-- =======================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    correo VARCHAR(255) NOT NULL UNIQUE,
    firma VARCHAR(50) NOT NULL,
    puesto VARCHAR(100) NOT NULL,
    normas TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_correo (correo),
    INDEX idx_firma (firma)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- =======================
-- Tabla: clients (Clientes)
-- =======================
CREATE TABLE IF NOT EXISTS clients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    folder TEXT,
    role ENUM(
        'cliente',
        'supervisor',
        'inspector'
    ) DEFAULT 'cliente',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_role (role)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- =======================
-- Tabla: assignments (Asignaciones)
-- =======================
CREATE TABLE IF NOT EXISTS assignments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    client_username VARCHAR(100),
    folder TEXT,
    assigned_to VARCHAR(100),
    assigned_by VARCHAR(100),
    assigned_at DATETIME,
    status ENUM(
        'subido',
        'asignado',
        'en_revision',
        'aceptado',
        'rechazado'
    ) DEFAULT 'subido',
    status_updated_at DATETIME,
    status_updated_by VARCHAR(100),
    folio VARCHAR(50) UNIQUE,
    uploaded_at DATETIME,
    last_edited_at DATETIME,
    last_edited_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_file_path (file_path (500)),
    INDEX idx_filename (filename),
    INDEX idx_client (client_username),
    INDEX idx_assigned_to (assigned_to),
    INDEX idx_status (status),
    INDEX idx_folio (folio),
    INDEX idx_uploaded_at (uploaded_at),
    FOREIGN KEY (client_username) REFERENCES clients (username) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- =======================
-- Tabla: comments (Comentarios)
-- =======================
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    assignment_id INT NOT NULL,
    author VARCHAR(100) NOT NULL,
    text TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    role VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_assignment (assignment_id),
    INDEX idx_author (author),
    FOREIGN KEY (assignment_id) REFERENCES assignments (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- =======================
-- Tabla: upload_history (Historial de Subidas)
-- =======================
CREATE TABLE IF NOT EXISTS upload_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(255),
    folder TEXT,
    uploaded_at DATETIME NOT NULL,
    url TEXT,
    username VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_filename (filename),
    INDEX idx_username (username),
    INDEX idx_uploaded_at (uploaded_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- =======================
-- Tabla: config (Configuración)
-- =======================
CREATE TABLE IF NOT EXISTS config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_config_key (config_key)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- =======================
-- Insertar configuración inicial
-- =======================
INSERT INTO
    config (
        config_key,
        config_value,
        description
    )
VALUES (
        'destination_folder',
        'uploads',
        'Carpeta de destino por defecto para archivos'
    )
ON DUPLICATE KEY UPDATE
    updated_at = CURRENT_TIMESTAMP;

-- =======================
-- Crear vistas útiles
-- =======================

-- Vista: Asignaciones con detalles completos
CREATE OR REPLACE VIEW v_assignments_full AS
SELECT
    a.id,
    a.filename,
    a.file_path,
    a.client_username,
    a.folder,
    a.assigned_to,
    a.assigned_by,
    a.assigned_at,
    a.status,
    a.status_updated_at,
    a.status_updated_by,
    a.folio,
    a.uploaded_at,
    a.last_edited_at,
    a.last_edited_by,
    c.role as client_role,
    COUNT(cm.id) as comment_count
FROM
    assignments a
    LEFT JOIN clients c ON a.client_username = c.username
    LEFT JOIN comments cm ON a.id = cm.assignment_id
GROUP BY
    a.id;

-- Vista: Estadísticas por inspector
CREATE OR REPLACE VIEW v_inspector_stats AS
SELECT
    assigned_to as inspector,
    COUNT(*) as total_asignaciones,
    SUM(
        CASE
            WHEN status = 'aceptado' THEN 1
            ELSE 0
        END
    ) as aceptadas,
    SUM(
        CASE
            WHEN status = 'rechazado' THEN 1
            ELSE 0
        END
    ) as rechazadas,
    SUM(
        CASE
            WHEN status = 'en_revision' THEN 1
            ELSE 0
        END
    ) as en_revision,
    SUM(
        CASE
            WHEN status = 'asignado' THEN 1
            ELSE 0
        END
    ) as pendientes
FROM assignments
WHERE
    assigned_to IS NOT NULL
GROUP BY
    assigned_to;

-- Vista: Estadísticas por cliente
CREATE OR REPLACE VIEW v_client_stats AS
SELECT
    client_username as cliente,
    COUNT(*) as total_archivos,
    SUM(
        CASE
            WHEN status = 'aceptado' THEN 1
            ELSE 0
        END
    ) as aceptados,
    SUM(
        CASE
            WHEN status = 'rechazado' THEN 1
            ELSE 0
        END
    ) as rechazados,
    SUM(
        CASE
            WHEN status IN ('asignado', 'en_revision') THEN 1
            ELSE 0
        END
    ) as en_proceso,
    SUM(
        CASE
            WHEN status = 'subido' THEN 1
            ELSE 0
        END
    ) as sin_asignar
FROM assignments
GROUP BY
    client_username;