import React, { useRef } from "react";

function MyFunction() {
  const box = useRef(0);

  const update = () => {
    box.current = 1000;
    console.log("update:", box.current);
  };

  return (
    <div>
      <button onClick={update}>Update!</button>
    </div>
  );
}

export default MyFunction;













// import React, { useRef } from "react";

// function MyFunction() {
//   const box = useRef(0);

//   const update = () => {
//     box.current = 1000;
//     console.log("update:", box.current);
//   };

//   return (
//     <div>
//       <button onClick={update}>Update!</button>
//     </div>
//   );
// }

// export default MyFunction;
