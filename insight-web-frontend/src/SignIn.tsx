import * as React from "react";

import Link from "@mui/material/Link";
import Box from "@mui/material/Box";

import Typography from "@mui/material/Typography";
import Container from "@mui/material/Container";

import { QRCodeSVG } from "qrcode.react";
import { API_BASE_URL } from "./Api";

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

export default function SignIn() {
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
          <QRCodeSVG
            value={
              API_BASE_URL +
              "/register?SESSION_ID=" +
              (globalThis as any).SESSION_ID
            }
            style={{ width: 300, height: 300 }}
          />
          ,
        </Box>
      </Box>
      <Copyright sx={{ mt: 8, mb: 4 }} />
    </Container>
  );
}
