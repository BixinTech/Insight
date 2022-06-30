import * as React from "react";

import Avatar from "@mui/material/Avatar";
import DialogTitle from "@mui/material/DialogTitle";
import Dialog from "@mui/material/Dialog";
import EditIcon from '@mui/icons-material/Edit';
import Typography from "@mui/material/Typography";

import IpBox from "./IpBox";

export interface SignInIpDialogProps {
  open: boolean;
  onClose: () => void;
}

export function SignInIpDialog(props: SignInIpDialogProps) {
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
          <EditIcon />
        </Avatar>
        <Typography>Insight</Typography>
      </DialogTitle>
      <IpBox />
    </Dialog>
  );
}
