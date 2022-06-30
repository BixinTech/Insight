import * as React from "react";

import Avatar from "@mui/material/Avatar";
import DialogTitle from "@mui/material/DialogTitle";
import Dialog from "@mui/material/Dialog";
import CameraAltOutlined from "@mui/icons-material/CameraAltOutlined";
import Typography from "@mui/material/Typography";

import SignIn from "./SignIn";

export interface SignInQrCodeDialogProps {
  open: boolean;
  onClose: () => void;
}

export function SignInQrCodeDialog(props: SignInQrCodeDialogProps) {
  const { onClose, open } = props;

  const handleClose = () => {
    onClose();
  };

  return (
    <Dialog onClose={handleClose} open={open}>
      <DialogTitle
        sx={{ display: "flex", justifyContent: "center", alignItems: "center" }}
      >
        <Avatar sx={{ m: 1, bgcolor: "secondary.main" }}>
          <CameraAltOutlined />
        </Avatar>
        <Typography>Insight</Typography>
      </DialogTitle>
      <SignIn />
    </Dialog>
  );
}
