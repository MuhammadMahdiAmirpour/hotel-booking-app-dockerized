// import React, { useEffect, useState } from "react";
// import { getAllRooms } from "../utils/ApiFunctions";
// import { Link } from "react-router-dom";
// import { Card, Carousel, Col, Container, Row } from "react-bootstrap";
//
// const RoomCarousel = () => {
//     const [rooms, setRooms] = useState([]);
//     const [errorMessage, setErrorMessage] = useState("");
//     const [isLoading, setIsLoading] = useState(false);
//
//     useEffect(() => {
//         const fetchRooms = async () => {
//             setIsLoading(true);
//             try {
//                 const data = await getAllRooms();
//                 if (Array.isArray(data)) {
//                     setRooms(data);
//                 } else {
//                     throw new Error("Unexpected data format");
//                 }
//             } catch (error) {
//                 setErrorMessage(error.message || "Failed to fetch rooms");
//             } finally {
//                 setIsLoading(false);
//             }
//         };
//
//         fetchRooms().then(r => {return r});
//         return () => {
//             // Clean up any resources or event listeners here
//         };
//     }, []);
//
//     const handleBookNow = (roomId) => {
//         // Implement logic to handle booking a room
//         console.log(`Booking room with ID: ${roomId}`);
//         // Redirect to the booking page or show a confirmation modal
//     };
//
//     if (isLoading) {
//         return <div className="mt-5">Loading rooms....</div>;
//     }
//     if (errorMessage) {
//         return <div className="text-danger mb-5 mt-5">Error: {errorMessage}</div>;
//     }
//
//     return (
//         <section className="bg-light mb-5 mt-5 shadow">
//             <Link to={"/browse-all-rooms"} className="hote-color text-center btn btn-hotel">
//                 Browse all rooms
//             </Link>
//
//             <Container>
//                 <Carousel indicators={false}>
//                     {[...Array(Math.ceil(rooms.length / 4))].map((_, index) => (
//                         <Carousel.Item key={index}>
//                             <Row>
//                                 {rooms.slice(index * 4, index * 4 + 4).map((room) => (
//                                     <Col key={room.id} className="mb-4" xs={12} md={6} lg={3}>
//                                         <Card>
//                                             <Link to={`/book-room/${room.id}`}>
//                                                 <Card.Img
//                                                     variant="top"
//                                                     src={`data:image/png;base64, ${room.photo}`}
//                                                     alt="Room Photo"
//                                                     className="w-100"
//                                                     style={{ height: "200px" }}
//                                                 />
//                                             </Link>
//                                             <Card.Body>
//                                                 <Card.Title className="hotel-color">{room.roomType}</Card.Title>
//                                                 <Card.Title className="room-price">${room.roomPrice}/night</Card.Title>
//                                                 <div className="flex-shrink-0">
//                                                     <button
//                                                         className="btn btn-hotel btn-sm"
//                                                         onClick={() => handleBookNow(room.id)}
//                                                     >
//                                                         Book Now
//                                                     </button>
//                                                 </div>
//                                             </Card.Body>
//                                         </Card>
//                                     </Col>
//                                 ))}
//                             </Row>
//                         </Carousel.Item>
//                     ))}
//                 </Carousel>
//             </Container>
//         </section>
//     );
// };
//
// export default RoomCarousel;

import React, { useEffect, useState } from "react"
import { getAllRooms } from "../utils/ApiFunctions"
import { Link } from "react-router-dom"
import { Card, Carousel, Col, Container, Row } from "react-bootstrap"

const RoomCarousel = () => {
	const [rooms, setRooms] = useState([{ id: "", roomType: "", roomPrice: "", photo: "" }])
	const [errorMessage, setErrorMessage] = useState("")
	const [isLoading, setIsLoading] = useState(false)

	useEffect(() => {
		setIsLoading(true)
		getAllRooms()
			.then((data) => {
				setRooms(data)
				setIsLoading(false)
			})
			.catch((error) => {
				setErrorMessage(error.message)
				setIsLoading(false)
			})
	}, [])

	if (isLoading) {
		return <div className="mt-5">Loading rooms....</div>
	}
	if (errorMessage) {
		return <div className=" text-danger mb-5 mt-5">Error : {errorMessage}</div>
	}

	return (
		<section className="bg-light mb-5 mt-5 shadow">
			<Link to={"/browse-all-rooms"} className="hote-color text-center">
				Browse all rooms
			</Link>

			<Container>
				<Carousel indicators={false}>
					{[...Array(Math.ceil(rooms.length / 4))].map((_, index) => (
						<Carousel.Item key={index}>
							<Row>
								{rooms.slice(index * 4, index * 4 + 4).map((room) => (
									<Col key={room.id} className="mb-4" xs={12} md={6} lg={3}>
										<Card>
											<Link to={`/book-room/${room.id}`}>
												<Card.Img
													variant="top"
													src={`data:image/png;base64, ${room.photo}`}
													alt="Room Photo"
													className="w-100"
													style={{ height: "200px" }}
												/>
											</Link>
											<Card.Body>
												<Card.Title className="hotel-color">{room.roomType}</Card.Title>
												<Card.Title className="room-price">${room.roomPrice}/night</Card.Title>
												<div className="flex-shrink-0">
													<Link to={`/book-room/${room.id}`} className="btn btn-hotel btn-sm">
														Book Now
													</Link>
												</div>
											</Card.Body>
										</Card>
									</Col>
								))}
							</Row>
						</Carousel.Item>
					))}
				</Carousel>
			</Container>
		</section>
	)
}

export default RoomCarousel

