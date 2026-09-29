.PHONY: install test serve dashboard demo

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

serve:
	uvicorn auditor.api.main:app --reload --port 8000

dashboard:
	cd dashboard && npm run dev

demo:
	uvicorn demo_target.app:app --host 127.0.0.1 --port 9000
