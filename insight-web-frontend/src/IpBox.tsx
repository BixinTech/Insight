import * as React from "react";

import Link from "@mui/material/Link";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import Container from "@mui/material/Container";
import { TextField, Button } from "@mui/material";
import Snackbar, { SnackbarOrigin } from "@mui/material/Snackbar";
import LinearProgress from "@mui/material/LinearProgress";

import Api from "./Api";

function Copyright(props: any) {
  return (
    <Typography
      variant="body2"
      color="text.secondary"
      align="center"
      {...props}
    >
      {"Copyright © "}
      <Link color="inherit" href="https://github.com/BixinTech/Insight">
        BixinTech Insight
      </Link>{" "}
      {new Date().getFullYear()}
      {"."}
    </Typography>
  );
}

export default function IpBox() {
  const [ip, setIp] = React.useState("");
  const [snackSuccessOpen, setSnackSuccessOpen] = React.useState(false);
  const [snackFailOpen, setSnackFailOpen] = React.useState(false);
  const [loading, setLoading] = React.useState(false);

  return (
    <Container component="main" maxWidth="xs">
      <Box
        sx={{
          marginTop: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Box>
          <TextField
            id="outlined-basic"
            label="IP Address"
            variant="outlined"
            onChange={(event) => {
              setIp(event.target.value);
            }}
          />
        </Box>
        <br />
        <Box>
          <Button
            variant="contained"
            onClick={() => {
              const url =
                "/register?SESSION_ID=" +
                (globalThis as any).SESSION_ID +
                "&ip=" +
                ip;
              console.log(url);
              setLoading(true);
              Api.get(url)
                .then((data) => {
                  setLoading(false);
                  console.log(data);
                  if ((data as any).code === 8000) {
                    setSnackSuccessOpen(true);
                  } else {
                    setSnackFailOpen(true);
                  }
                })
                .catch((error) => {
                  setLoading(false);
                });
            }}
          >
            Register
          </Button>
          <Snackbar
            anchorOrigin={{ vertical: "top", horizontal: "center" }}
            open={snackSuccessOpen}
            autoHideDuration={6000}
            onClose={() => {
              setSnackSuccessOpen(false);
            }}
            message="Register by IP succeed!"
            key={"top" + "center"}
          />
          <Snackbar
            anchorOrigin={{ vertical: "top", horizontal: "center" }}
            open={snackFailOpen}
            autoHideDuration={6000}
            onClose={() => {
              setSnackFailOpen(false);
            }}
            message="Register by IP failed!"
            key={"top" + "center"}
          />
        </Box>
        {loading ? (
          <Box sx={{ width: "100%" }}>
            <br />
            <LinearProgress />
          </Box>
        ) : null}
      </Box>
      <Copyright sx={{ mt: 8, mb: 4 }} />
    </Container>
  );
}
