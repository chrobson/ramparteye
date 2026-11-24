-- 0002_roles.sql: built-in roles and their permissions.
INSERT INTO roles (name, builtin) VALUES
    ('Admin', true), ('Operator', true), ('Analyst', true), ('Viewer', true);

INSERT INTO role_permissions (role_id, perm)
SELECT r.id, p.perm FROM roles r
JOIN (VALUES
    ('Admin', 'targets.read'), ('Admin', 'targets.write'), ('Admin', 'scans.run'),
    ('Admin', 'results.read'), ('Admin', 'results.edit'), ('Admin', 'signatures.write'),
    ('Admin', 'export'), ('Admin', 'users.admin'), ('Admin', 'settings.admin'),
    ('Operator', 'targets.read'), ('Operator', 'targets.write'), ('Operator', 'scans.run'),
    ('Operator', 'results.read'), ('Operator', 'results.edit'), ('Operator', 'signatures.write'),
    ('Operator', 'export'),
    ('Analyst', 'targets.read'), ('Analyst', 'results.read'), ('Analyst', 'results.edit'),
    ('Analyst', 'export'),
    ('Viewer', 'targets.read'), ('Viewer', 'results.read')
) AS p(role, perm) ON p.role = r.name;
