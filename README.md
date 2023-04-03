# SML (server monitor light)

A simple single-node server performance monitor with notification.

## Usage

Clone this repo:

``` bash
git clone https://github.com/ertuil/sml.git
```

Install dependence:

```
pip install -r requirements
apt install smartmontools  # S.M.A.R.T information (For Debian or Ubuntu)
```

copy `config.example.py` to `config.py`, and change the configurations as needed.

Run the single shot with

``` bash
python3 main.py
```

Or, change the configure to `interval = 300`. The `sml` works like a daemon and collects information with every 300 seconds.

## Copy and License

see `LICENSE`