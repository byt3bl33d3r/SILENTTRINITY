# How to contribute

## Style and linting

### Python

1. Follow the Python Style Guide (PSG) as formulated in PEP-8: http://www.python.org/dev/peps/pep-0008/
2. Use `pylint` to lint code.

The critical points are:

* Use spaces; never use tabs
* 4 space indentation
* 79 character line limit
* Variables, functions and methods should be `lower_case_with_underscores`
* Classes are `TitleCase`

And other preferences:

* Use ' and not " as the quote character by default
* When writing a method, consider if it is really a method (needs `self`) or if it would be better as a utility function
* When writing a `@classmethod`, consider if it really needs the class (needs `cls`) or it would be better as a utility function or factory class

#### Python Version

As a rule, all Python code should be written to support Python 3.7 or greater.

## Development environment.

Follow the instructions written in the Wiki page: [Setting up your development environment](https://github.com/byt3bl33d3r/SILENTTRINITY/wiki/Setting-up-your-development-environment)

## Pull Request.

1. Fork this repository.
2. Create a breanch from `master`.
3. Submit your PR using examples.
4. Wait until your PR is approved.
