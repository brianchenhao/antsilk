# antsilk

**Drop-in security middleware for Python web applications.**

antsilk is a unified security layer for FastAPI and Flask applications, bundling a Web Application Firewall (WAF), identity validation, and structured security logging behind a single middleware install. The goal is sensible defaults out of the box, with room to extend when you need more.

## Status

Under active development. This package on PyPI is a placeholder reserving the name; the real `v0.1.0` release is coming soon.

## What's planned for v0.1.0

- **WAF**: request inspection and rule-based filtering for common web attacks
- **Identity gateway**: token validation and request authentication helpers
- **Structured logging**: machine-readable security events for your existing observability pipeline
- **One-line install**: drop into FastAPI or Flask apps without rewiring middleware stacks

## Links

antsilk.com (coming soon)

## License

MIT
