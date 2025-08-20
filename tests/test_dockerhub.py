import pytest
from concil import dockerhub


@pytest.mark.parametrize(
    "url, expected_repository, expected_tag, expected_hostname, expected_port, expected_username, expected_password",
    [
        (
            "docker://registry.hub.docker.com/library/ubuntu:latest",
            "library/ubuntu",
            "latest",
            "registry.hub.docker.com",
            None,
            None,
            None,
        ),
        (
            "docker://registry.hub.docker.com/library/ubuntu",
            "library/ubuntu",
            "latest",
            "registry.hub.docker.com",
            None,
            None,
            None,
        ),
        (
            "docker://user:pass@registry.hub.docker.com/library/ubuntu:18.04",
            "library/ubuntu",
            "18.04",
            "registry.hub.docker.com",
            None,
            "user",
            "pass",
        ),
        (
            "docker://localhost:5000/my-image:test",
            "my-image",
            "test",
            "localhost",
            5000,
            None,
            None,
        ),
        (
            "http://localhost:5000/my-image",
            "my-image",
            "latest",
            "localhost",
            5000,
            None,
            None,
        ),
        (
            "https://localhost/my-image",
            "my-image",
            "latest",
            "localhost",
            None,
            None,
            None,
        ),
    ],
)
def test_parse_docker_url(
    url,
    expected_repository,
    expected_tag,
    expected_hostname,
    expected_port,
    expected_username,
    expected_password,
):
    """Tests that parse_docker_url correctly parses various Docker URL formats."""
    result = dockerhub.parse_docker_url(url)
    assert result.repository == expected_repository
    assert result.tag == expected_tag
    assert result.hostname == expected_hostname
    if result.scheme != "store":
        assert result.port == expected_port
    assert result.username == expected_username
    assert result.password == expected_password


def test_dockerhub_init():
    """Tests that DockerHub.__init__ correctly parses the docker URL."""
    hub = dockerhub.DockerHub(
        "docker://user:pass@registry.hub.docker.com/library/ubuntu:18.04"
    )
    assert hub.username == "user"
    assert hub.password == "pass"
    assert hub.repository == "library/ubuntu"
    assert hub.tag == "18.04"
    assert hub.url == "https://registry.hub.docker.com/v2/library/ubuntu"


def test_dockerhub_request_success(mocker):
    """Tests a successful request."""
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_session_request = mocker.patch(
        "requests.Session.request", return_value=mock_response
    )

    hub = dockerhub.DockerHub("docker://registry.hub.docker.com/library/ubuntu:latest")
    response = hub.request("GET", "http://example.com")

    assert response == mock_response
    mock_session_request.assert_called_once_with("GET", "http://example.com")


def test_dockerhub_request_with_login(mocker):
    """Tests a request that requires login."""
    mock_unauthorized_response = mocker.Mock()
    mock_unauthorized_response.status_code = 401
    mock_unauthorized_response.headers = {
        "Www-Authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull"'
    }

    mock_token_response = mocker.Mock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {"token": "my-secret-token"}

    mock_success_response = mocker.Mock()
    mock_success_response.status_code = 200

    mock_session_request = mocker.patch(
        "requests.Session.request",
        side_effect=[
            mock_unauthorized_response,
            mock_token_response,
            mock_success_response,
        ],
    )

    mocker.patch("getpass.getpass", return_value="password")
    mocker.patch("builtins.input", return_value="user")

    hub = dockerhub.DockerHub("docker://registry.hub.docker.com/library/ubuntu:latest")
    response = hub.request("GET", "http://example.com")

    assert response == mock_success_response
    assert mock_session_request.call_count == 3
    assert hub.session.headers["Authorization"] == "Bearer my-secret-token"


def test_dockerhub_request_failure(mocker):
    """Tests a failed request."""
    mock_response = mocker.Mock()
    mock_response.status_code = 404
    mock_response.json.return_value = {
        "errors": [{"code": "NOT_FOUND", "message": "not found"}]
    }
    mocker.patch("requests.Session.request", return_value=mock_response)

    hub = dockerhub.DockerHub("docker://registry.hub.docker.com/library/ubuntu:latest")
    with pytest.raises(RuntimeError, match="Status: 404"):
        hub.request("GET", "http://example.com/notfound")
