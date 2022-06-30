import * as React from "react";

import Link from "@mui/material/Link";
import Box from "@mui/material/Box";

import Typography from "@mui/material/Typography";
import Container from "@mui/material/Container";

import { TextField, Button } from "@mui/material";
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
              Api.get(url)
                .then((data) => {
                  console.log(data);
                  if ((data as any).code === 8000) {

                  }
                })
                .catch((error) => {});
            }}
          >
            Register
          </Button>
        </Box>
      </Box>
      <Copyright sx={{ mt: 8, mb: 4 }} />
    </Container>
  );
}
