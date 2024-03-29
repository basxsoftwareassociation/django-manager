#!/usr/bin/python3
import os
import random
import re
import string
import subprocess
import tempfile
import tokenize

import click
import nginx

# config

APP_DIR = "/var/www"
DJANGO_USER = "www-data"
NGINX_SITES_DIR = "/etc/nginx/sites-available"
NGINX_ENABLED_SITES_DIR = "/etc/nginx/sites-enabled"
UWSGI_CONF_DIR = "/etc/uwsgi-emperor/vassals"
ADMIN_EMAIL = "monitor@basx.dev"
SUDO_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


# helpers


def safedomainstr(domain):
    return domain.replace(".", "_")


# table is row-first 2d array
def print_tabel(table):
    maxwidths = [max([len((cell or "")) for cell in column]) for column in zip(*table)]
    totalwidth = sum(maxwidths) + len(maxwidths) * 3 + 1
    print("+" + (totalwidth - 2) * "-" + "+")
    for row in table:
        for i, cell in enumerate(row):
            cell = cell or ""
            cell += (maxwidths[i] - len(cell)) * " "
            print(f"| {cell} ", end="")
        print("|")
        print("+" + (totalwidth - 2) * "-" + "+")


def run_root(
    command, application_dir=APP_DIR, user="root", env={}, check=True, **kwargs
):
    env["VIRTUAL_ENV"] = f"{application_dir}/.venv"
    env["PATH"] = f"{application_dir}/.venv/bin:{SUDO_PATH}"
    stdout = None if "capture_output" in kwargs else subprocess.DEVNULL
    print(f"({user}) " + " ".join(command))
    return subprocess.run(
        [
            "sudo",
            "-u",
            user,
            *[f"{k}={v}" for k, v in env.items()],
            "sh",
            "-c",
            " ".join(command),
        ],
        cwd=application_dir,
        check=check,
        stdout=stdout,
        **kwargs,
    )


def djangomanage(command, domain, check=True, user=DJANGO_USER, **kwargs):
    application_dir = os.path.join(APP_DIR, domain)
    projectname = get_projectname(domain)
    venv = f"VIRTUAL_ENV={application_dir}/.venv"
    path = f'PATH={application_dir}/.venv/bin:{os.environ["PATH"]}'
    command = (
        ["python", "manage.py"]
        + command
        + [f"--settings={projectname}.settings.production"]
    )
    stdout = None if "capture_output" in kwargs else subprocess.DEVNULL
    print(f"({user}) " + " ".join(command))
    subprocess.run(
        ["sudo", "-u", user, venv, path, "sh", "-c", " ".join(command)],
        cwd=application_dir,
        check=check,
        stdout=stdout,
        **kwargs,
    )


def randomstring(n=24):
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for i in range(n))


def isdomain(domain):
    return re.match(r"^[a-zA-Z-\d]{1,63}(\.[a-zA-Z\d-]{1,63})*$", domain) is not None


class DomainParamType(click.ParamType):
    name = "domain"

    def convert(self, value, param, ctx):
        if not isdomain(value):
            self.fail("%s is not a valid domainname" % value, param, ctx)
        return value


def finddomains(dir):
    for root, dirs, files in os.walk(dir):
        for file in files:
            path = os.path.join(root, file)
            config = nginx.loadf(path)
            for child in config.servers:
                for i in child.keys:
                    if i.name == "server_name" and isdomain(i.value):
                        yield i.value, path


def findapplications():
    return filter(get_projectname, filter(isdomain, os.listdir(APP_DIR)))


def get_projectname(domain):
    # TODO: make this a little bit less magic
    applicationpath = get_application_dir(domain)
    if applicationpath is None:
        return None
    wsgipath = os.path.join(applicationpath, "wsgi.py")
    if not os.path.exists(wsgipath) or not os.path.isfile(wsgipath):
        return None
    with open(wsgipath, "rb") as f:
        wsgitokens = tokenize.tokenize(f.readline)
        found_variable = False
        projectname = None
        for token in wsgitokens:
            if (
                not found_variable
                and token[0] == tokenize.STRING
                and "DJANGO_SETTINGS_MODULE" in token[1]
            ):
                found_variable = True
            elif found_variable and token[0] == tokenize.STRING:
                projectname = token[1].replace("'", "").replace('"', "").split(".")[0]
                break
    return projectname


def is_git(domain):
    application_dir = os.path.join(APP_DIR, domain)
    return os.path.isdir(os.path.join(application_dir, ".git"))


def is_hg(domain):
    application_dir = os.path.join(APP_DIR, domain)
    return os.path.isdir(os.path.join(application_dir, ".hg"))


def vcs_remote_url(domain):
    application_dir = os.path.join(APP_DIR, domain)
    if is_git(domain):
        run_root(
            ["git", "remote", "get-url", "origin"],
            application_dir,
            capture_output=True,
            text=True,
        ).stdout.strip()
    elif is_hg(domain):
        run_root(
            ["hg", "paths", "default"], application_dir, capture_output=True, text=True
        ).stdout.strip()
    else:
        raise Exception(f"Domain {domain} uses neither git nor hg")


def vcs_branch(domain):
    application_dir = os.path.join(APP_DIR, domain)
    if is_git(domain):
        run_root(
            ["git", "branch"], application_dir, capture_output=True, text=True
        ).stdout.strip()
    elif is_hg(domain):
        run_root(
            ["hg", "branch"], application_dir, capture_output=True, text=True
        ).stdout.strip()
    else:
        raise Exception(f"Domain {domain} uses neither git nor hg")


def vcs_pull(domain):
    application_dir = os.path.join(APP_DIR, domain)
    if is_git(domain):
        run_root(["git", "pull"], application_dir)
    elif is_hg(domain):
        run_root(["hg", "pull", "-u"], application_dir)
    else:
        raise Exception(f"Domain {domain} uses neither git nor hg")


def vcs_clone(domain, clone_url):
    application_dir = os.path.join(APP_DIR, domain)

    if clone_url.startswith("ssh://git") or clone_url.startswith("https://git"):
        run_root(["git", "clone", clone_url, application_dir], application_dir)
    elif clone_url.startswith("ssh://hg") or clone_url.startswith("https://hg"):
        run_root(["hg", "clone", clone_url, application_dir], application_dir)
    else:
        raise Exception(f"Not sure whether {clone_url} uses git or hg")


def vcs_select_branch(domain, branch):
    application_dir = os.path.join(APP_DIR, domain)
    if is_git(domain):
        run_root(["git", "checkout", branch], application_dir)
    elif is_hg(domain):
        run_root(["hg", "update", branch], application_dir)
    else:
        raise Exception(f"Domain {domain} uses neither git nor hg")


def get_branch(domain):
    if get_application_dir(domain) is None:
        return ""
    try:
        return vcs_branch(domain)
    except subprocess.CalledProcessError:
        return ""


def get_repo(domain):
    application_dir = get_application_dir(domain)
    if application_dir is None:
        return None
    return vcs_remote_url(domain)


def get_application_dir(domain):
    path = os.path.join(APP_DIR, domain)
    if os.path.exists(path) and os.path.isdir(path):
        return path
    return None


def get_project_dir(domain):
    application_dir = get_application_dir(domain)
    if application_dir is not None and get_projectname(domain) is not None:
        project_dir = os.path.join(application_dir, get_projectname(domain))
        if os.path.exists(project_dir) and os.path.isdir(project_dir):
            return project_dir
    return None


def get_local_config_file(domain):
    project_dir = get_project_dir(domain)
    if project_dir is None:
        return None
    local_config_path = os.path.join(project_dir, "settings", "local.py")
    if os.path.exists(local_config_path) and os.path.isfile(local_config_path):
        return local_config_path
    return None


def get_local_config(domain):
    local = get_local_config_file(domain)
    if local is None:
        return None
    configs = {}
    config_content = (
        run_root(["cat", local], capture_output=True).stdout.decode().strip()
    )
    exec(config_content, {}, configs)
    return configs


def get_db_config(domain):
    c = get_local_config(domain)
    if c and "DATABASES" in c and "default" in c["DATABASES"]:
        return c["DATABASES"]["default"]
    return None


def setupwebserver(domain, selfsigned=False):
    nginx_config = f"""server {{
    server_name {domain};
    include /etc/nginx/sites-available/django-app;
    """
    if selfsigned:
        nginx_config += f"""
        ssl_certificate /etc/ssl/certs/{domain}.crt;
        ssl_certificate_key /etc/ssl/private/{domain}.key;
    """
    nginx_config += """}"""
    nginx_site = os.path.join(NGINX_SITES_DIR, domain)
    nginx_en_site = os.path.join(NGINX_ENABLED_SITES_DIR, domain)
    uwsgi_file = os.path.join(UWSGI_CONF_DIR, f"{domain}.ini")
    uwsgi_template = os.path.join(UWSGI_CONF_DIR, "django.ini.skel")
    run_root(["dd", f"of={nginx_site}"], input=nginx_config.encode())
    run_root(["ln", "-f", "-s", nginx_site, nginx_en_site])
    run_root(["ln", "-f", "-s", uwsgi_template, uwsgi_file])
    if selfsigned:
        run_root(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                f"/etc/ssl/private/{domain}.key",
                "-out",
                f"/etc/ssl/certs/{domain}.crt",
            ]
        )
        run_root(["systemctl", "restart", "nginx"])
    else:
        run_root(
            [
                "certbot",
                "--agree-tos",
                "--email",
                "info@basx.dev",
                "--non-interactive",
                "--no-redirect",
                "--nginx",
                "-d",
                domain,
            ]
        )


@click.group()
def cli():
    pass


@click.command()
@click.option("--raw", is_flag=True)
def ls(raw):
    if raw:
        for i in findapplications():
            print(i)
    else:
        print_tabel(
            [[i, get_projectname(i), get_branch(i)] for i in findapplications()]
        )


@click.command()
@click.argument("domain", type=DomainParamType())
@click.argument("clone_url")
@click.option("--branch", default="main")
@click.option("--selfsigned/--no-selfsigned", default=False)
@click.option("--localsettings", default="")
@click.pass_context
def new(context, domain, clone_url, branch, selfsigned, localsettings):
    application_dir = get_application_dir(domain)
    if application_dir is not None:
        print(f"'{application_dir}'exists already")
        if click.confirm(f"Remove {application_dir} completely?"):
            if click.confirm(
                f"This will remove ALL data of {domain}, are you really sure?"
            ):
                context.invoke(rm, domain=domain)
            else:
                return
        else:
            return
    else:
        application_dir = os.path.join(APP_DIR, domain)
    run_root(["mkdir", application_dir])
    vcs_clone(domain, clone_url)
    if branch == "main" and is_hg(domain):
        branch = "default"
    vcs_select_branch(domain, branch)
    run_root(["python3", "-m", "venv", ".venv"], application_dir)
    run_root(["pip", "install", "-r", "requirements.txt"], application_dir)
    local_config = [
        f'SECRET_KEY = "{randomstring(50)}"',
        f'ALLOWED_HOSTS = ["{domain}"]',
        f'STATIC_ROOT = "{os.path.join(application_dir, "static")}"',
        f'MEDIA_ROOT = "{os.path.join(application_dir, "media")}"',
        f'ADMINS = [("Monitor", "{ADMIN_EMAIL}"), ]',
        "",
    ]
    projectname = get_projectname(domain)
    local_config.append(f'CELERY_BROKER_URL = "amqp://localhost/{domain}"')
    if localsettings:
        with open(localsettings, "r") as f:
            local_config.extend(f.readlines())

    local_settings = os.path.join(application_dir, projectname, "settings", "local.py")
    run_root(["dd", "of=" + local_settings], input="\n".join(local_config).encode())
    run_root(["chown", f"{DJANGO_USER}:{DJANGO_USER}", local_settings], application_dir)
    run_root(["chmod", "a-rwx", local_settings], application_dir)
    run_root(["chmod", "u+rw", local_settings], application_dir)
    run_root(["chown", f"{DJANGO_USER}:{DJANGO_USER}", "."], application_dir)
    djangomanage(["migrate", "--noinput"], domain)
    run_root(["chmod", "a-rwx", "db.sqlite3"], application_dir)
    run_root(["chmod", "u+rw", "db.sqlite3"], application_dir)
    run_root(["mkdir", "-p", "media"], application_dir)
    run_root(["chown", f"{DJANGO_USER}:{DJANGO_USER}", "-R", "media"], application_dir)
    run_root(["chmod", "a-rwx", "media"], application_dir)
    run_root(["chmod", "u+rwx", "media"], application_dir)
    pw = randomstring()
    createsucmd = (
        "'from django.contrib.auth.models import User;"
        f' User.objects.create_superuser("admin", "", "{pw}")\''
    )
    djangomanage(["shell", "-c", createsucmd], domain)

    # set up rabbitmq
    run_root(["rabbitmqctl", "add_vhost", domain], check=False)
    run_root(
        [
            "rabbitmqctl",
            "set_permissions",
            "-p",
            domain,
            "guest",
            '".*"',
            '".*"',
            '".*"',
        ],
        check=False,
    )

    # webserver needs to be setup before update
    setupwebserver(domain, selfsigned)

    context.invoke(update, domain=domain)
    print(f"django admin-password: {pw}")


@click.command()
@click.argument("domain", type=DomainParamType())
@click.option("--full-pip-upgrade/--no-full-pip-upgrade", default=False)
def update(domain, full_pip_upgrade):
    application_dir = os.path.join(APP_DIR, domain)
    vcs_pull(domain)
    if full_pip_upgrade:
        run_root(
            [
                "pip",
                "install",
                "--upgrade",
                "-r",
                "requirements.txt",
            ],
            application_dir,
        )
    else:
        run_root(
            [
                "pip",
                "install",
                "--upgrade",
                "-r",
                "requirements.txt",
            ],
            application_dir,
        )

    djangomanage(["migrate", "--noinput"], domain)
    djangomanage(
        ["compilemessages", "-l", "en", "-l", "th", "-l", "de"],
        domain,
        user="root",
        check=False,
    )
    djangomanage(["collectstatic", "--no-input"], domain)
    djangomanage(["check"], domain)
    run_root(["touch", os.path.join(UWSGI_CONF_DIR, f"{domain}.ini")], check=False)


@click.command()
@click.pass_context
def update_all(context):
    for domain in findapplications():
        context.invoke(update, domain=domain)


@click.command()
@click.argument("srcdomain", type=DomainParamType())
@click.argument("dstdomain", type=DomainParamType())
@click.pass_context
def cp(context, srcdomain, dstdomain):
    assert srcdomain != dstdomain, "Source and destionation domain cannot be the same"
    application_dir1 = os.path.join(APP_DIR, srcdomain)
    application_dir2 = os.path.join(APP_DIR, dstdomain)
    projectname1 = get_projectname(srcdomain)
    projectname2 = get_projectname(dstdomain)
    if projectname1 is None:
        print(f"{srcdomain} does not exists")
        return
    if projectname2 is None:
        if click.confirm(f"{dstdomain} does not exists, do you want to create it?"):
            context.invoke(
                new,
                domain=dstdomain,
                clone_url=get_repo(srcdomain),
                branch=get_branch(srcdomain),
            )
        projectname2 = get_projectname(dstdomain)
    if projectname1 != projectname2:
        print(f"{srcdomain} and {dstdomain} must use the same django project")
        return

    # copy database
    run_root(
        [
            "cp",
            os.path.join(application_dir1, "db.sqlite3"),
            os.path.join(application_dir2, "db.sqlite3"),
        ],
        user=DJANGO_USER,
    )

    # copy media files
    run_root(["rm", "-rf", "media"], application_dir2)
    run_root(
        [
            "cp",
            "-r",
            os.path.join(application_dir1, "media"),
            os.path.join(application_dir2, "media"),
        ],
        user=DJANGO_USER,
    )

    # print the diff of local.py
    run_root(["echo", "diff for local.py:"], user=DJANGO_USER)
    run_root(
        [
            "diff",
            os.path.join(application_dir1, projectname1, "settings", "local.py"),
            os.path.join(application_dir2, projectname2, "settings", "local.py"),
        ],
        check=False,
        user=DJANGO_USER,
    )

    # restart uwsgi
    run_root(["touch", os.path.join(UWSGI_CONF_DIR, f"{dstdomain}.ini")])


@click.command()
@click.argument("srcdomain", type=DomainParamType())
@click.argument("dstdomain", type=DomainParamType())
@click.pass_context
def mv(context, srcdomain, dstdomain):
    assert srcdomain != dstdomain, "Source and destionation domain cannot be the same"
    context.invoke(cp, srcdomain=srcdomain, dstdomain=dstdomain)
    context.invoke(rm, domain=srcdomain)


@click.command()
@click.argument("domain", type=DomainParamType())
def rm(domain):
    application_dir = os.path.join(APP_DIR, domain)
    run_root(["rm", "-rf", application_dir])
    run_root(["rm", "-f", os.path.join(UWSGI_CONF_DIR, f"{domain}.ini")])
    run_root(["rm", "-f", os.path.join(NGINX_SITES_DIR, domain)])
    run_root(["rm", "-f", os.path.join(NGINX_ENABLED_SITES_DIR, domain)])
    run_root(["nginx", "-t"])
    run_root(["systemctl", "restart", "nginx"])
    if click.confirm("Should the certificate be removed as well (if existing)?"):
        run_root(
            [
                "certbot",
                "--agree-tos",
                "--email",
                "info@basx.dev",
                "revoke",
                "--delete-after-revoke",
                "--cert-name",
                domain,
            ],
            check=False,
        )
        run_root(
            [
                "rm",
                "-f",
                f"/etc/ssl/certs/{domain}.crt",
                f"/etc/ssl/private/{domain}.key",
            ]
        )


cli.add_command(ls)
cli.add_command(new)
cli.add_command(update)
cli.add_command(update_all)
cli.add_command(cp)
cli.add_command(mv)
cli.add_command(rm)


if __name__ == "__main__":
    cli()
